"""Compact QA networking must preserve foreign projects and avoid host/Docker routes."""

import ipaddress
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests import network_pool as pool


def test_subnets_avoid_existing_docker_networks_and_host_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "inspect" in command:
            output = [{"Name": "foreign", "IPAM": {"Config": [{"Subnet": "10.240.0.0/16"}]}}]
        elif command[0] == "ip":
            output = [{"dst": "10.241.0.0/16"}]
        else:
            return subprocess.CompletedProcess(command, 0, "foreign-id\n", "")
        return subprocess.CompletedProcess(command, 0, json.dumps(output), "")

    monkeypatch.setenv("CVE_TEST_NETWORK_POOL", "10.240.0.0/12")
    monkeypatch.setattr(pool, "SYSTEM_RUN", run)
    monkeypatch.setattr(pool, "RESERVED", {})
    first, second = (ipaddress.ip_network(pool.subnet(name)) for name in ("own-a", "own-b"))
    assert first.prefixlen == second.prefixlen == 28
    assert not first.overlaps(second)
    assert all(
        not network.overlaps(ipaddress.ip_network(used))
        for network in (first, second)
        for used in ("10.240.0.0/16", "10.241.0.0/16")
    )
    assert pool.subnet("own-a") == str(first)


@pytest.mark.parametrize("project", ["cve-db-test-own", "foreign-production"])
def test_process_hook_only_adds_overlay_for_isolated_project_names(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    project: str,
) -> None:
    captured = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    target = tmp_path / "networks.json"
    monkeypatch.setattr(pool, "ACTIVE", True)
    monkeypatch.setattr(pool, "SYSTEM_RUN", run)
    monkeypatch.setattr(pool, "overlay", lambda root, name: target)
    monkeypatch.setattr(subprocess, "run", subprocess.run)
    monkeypatch.setenv("CVE_TEST_COMPACT_NETWORKS", "1")
    pool.pytest_configure(None)
    command = [
        "docker",
        "compose",
        "--project-name",
        project,
        "-f",
        str(tmp_path / "compose.yml"),
        "up",
        "-d",
        "cve-postgres",
    ]
    subprocess.run(command, check=True)
    assert (str(target) in captured[0]) == project.startswith("cve-db-test-")
    assert captured[0][-3:] == command[-3:]
    assert captured[0][captured[0].index("-f") + 1] == str(tmp_path / "compose.yml")


@pytest.mark.parametrize("missing_only", [True, False])
def test_network_inspection_tolerates_only_concurrent_removal(
    monkeypatch: pytest.MonkeyPatch, missing_only: bool
) -> None:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "inspect" in command:
            error = (
                "Error response from daemon: network removed-id not found\n"
                if missing_only
                else "permission denied\n"
            )
            return subprocess.CompletedProcess(command, 1, "[]", error)
        if command[0] == "ip":
            return subprocess.CompletedProcess(command, 0, "[]", "")
        return subprocess.CompletedProcess(command, 0, "removed-id\n", "")

    monkeypatch.setattr(pool, "SYSTEM_RUN", run)
    monkeypatch.setattr(pool, "RESERVED", {})
    if missing_only:
        assert ipaddress.ip_network(pool.subnet("isolated")).prefixlen == 28
    else:
        with pytest.raises(subprocess.CalledProcessError):
            pool.subnet("isolated")
