"""Unrestricted SSH destinations retain unprivileged, fixed collection semantics."""

import json
import socket
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml
from cve_api.ansible.schemas import Connection
from cve_automation import execute
from cve_automation.service import destination
from pydantic import ValidationError

from scripts.automation_executor import network
from scripts.database import manage as db
from scripts.infrastructure import network as infrastructure_network
from scripts.infrastructure.manage import load_config


@pytest.mark.parametrize(
    "address", ["8.8.8.8", "192.168.1.2", "127.0.0.1", "169.254.1.2", "::1", "2001:db8::1"]
)
def test_any_target_address_is_accepted(address: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assert Connection(version=0, host=address, username="collector").host == address
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(0, 0, 0, "", (address, 22))])
    assert destination(address, 22) == address


def test_removed_network_setting_is_no_longer_public(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    env = tmp_path / "obsolete.env"
    env.write_text((root / ".env.example").read_text() + 'ANSIBLE_ALLOWED_NETWORKS=["0.0.0.0/0"]\n')
    with pytest.raises(ValueError):
        load_config(env)


@pytest.mark.parametrize(
    "fields",
    [
        {"username": "root"},
        {"use_sudo": True},
        {"sudo_password": "not-used"},  # pragma: allowlist secret
    ],
)
def test_api_rejects_privileged_configuration(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Connection.model_validate(
            {"version": 0, "host": "host.example.org", "username": "collector", **fields}
        )


@pytest.mark.parametrize("fields", [{"username": "root"}, {"use_sudo": True}])
def test_runner_refuses_existing_privileged_profiles(
    fields: dict[str, Any], tmp_path: Path
) -> None:
    plan = {
        "address": "127.0.0.1",
        "port": 22,
        "action": "collect",
        "username": "collector",
        **fields,
    }
    assert execute.run(plan, tmp_path) == {
        "success": False,
        "error_code": "unprivileged_account_required",
    }
    assert not list(tmp_path.iterdir())


def test_playbook_uses_only_read_modules_on_target() -> None:
    play = yaml.safe_load(files("cve_automation").joinpath("playbooks/collect.yml").read_text())[0]
    assert play["become"] is False
    tasks = [task for task in play["tasks"] if task.get("delegate_to") != "localhost"]
    modules = {key for task in tasks for key in task if key.startswith("ansible.builtin.")}
    assert modules <= {
        "ansible.builtin.command",
        "ansible.builtin.setup",
        "ansible.builtin.package_facts",
        "ansible.builtin.service_facts",
    }
    assert tasks[0]["failed_when"] == "target_uid.stdout == '0'"
    for task in tasks:
        if "ansible.builtin.command" in task:
            assert task["changed_when"] is False


def test_namespace_guard_allows_configured_ipv4_and_ipv6_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config(overrides={"SECRETS_BASE": str(tmp_path)})
    (tmp_path / "ansible" / config.project).mkdir(parents=True)
    monkeypatch.setattr("scripts.application.manage.identity", lambda *a: {"State": {"Pid": 123}})
    monkeypatch.setattr("scripts.application.manage.peer", lambda *a: "172.20.0.2")
    monkeypatch.setattr(db, "address", lambda *a: "172.20.0.3")
    session = MagicMock()
    session.__enter__.return_value.execute.return_value.fetchall.return_value = [
        {"host": "8.8.8.8", "port": 22},
        {"host": "2001:db8::1", "port": 2222},
    ]
    monkeypatch.setattr(db, "connect", lambda *a: session)
    monkeypatch.setattr(network, "destination", lambda host, port: host)
    applied: list[str] = []

    def namespace(pid: int, args: list[str], **kwargs: Any) -> Any:
        if args == ["nft", "-f", "-"]:
            applied.append(kwargs["input"])
        return SimpleNamespace(stdout="net:[123]" if args[0] == "readlink" else "")

    monkeypatch.setattr(infrastructure_network, "namespace_command", namespace)
    network.install_guard(config)
    assert len(applied) == 1
    assert "ip daddr 8.8.8.8 tcp dport 22 accept" in applied[0]
    assert "ip6 daddr 2001:db8::1 tcp dport 2222 accept" in applied[0]
    assert "counter reject" in applied[0]
    assert json.loads((tmp_path / "ansible" / config.project / "network-proof.json").read_text())
