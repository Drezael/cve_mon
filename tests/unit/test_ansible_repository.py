"""Repository-local collection and immutable internal-submit receipts."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from scripts.ansible import manage, submit


def config(path: Path, value: dict[str, Any]) -> Path:
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def test_packaged_playbooks_are_the_repository_sources(repository_root: Path) -> None:
    for name in ("collect.yml", "connection-test.yml"):
        source = repository_root / "services/automation/src/cve_automation/playbooks" / name
        assert (
            files("cve_automation").joinpath("playbooks/" + name).read_bytes()
            == source.read_bytes()
        )


@pytest.mark.parametrize("change", [{"username": "root"}, {"use_sudo": True}])
def test_local_collector_refuses_privileged_profiles(
    tmp_path: Path, change: dict[str, Any]
) -> None:
    path = config(tmp_path / "connection.json", {"username": "collector", **change})
    with pytest.raises(ValueError, match="unprivileged"):
        manage.collect(path)


def test_local_probe_never_reads_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = config(
        tmp_path / "connection.json",
        {
            "host": "host.example.test",
            "username": "collector",
            "private_key_file": "/not/read",
        },
    )
    monkeypatch.setattr(manage, "destination", lambda *_a: "192.0.2.1")
    calls = []

    def run(plan: dict[str, Any], root: Path) -> dict[str, Any]:
        assert plan["credentials"] == {}
        assert plan["use_sudo"] is False
        calls.append(plan["action"])
        return {"success": True, "host_key": "ssh-ed25519 public-fixture"}

    monkeypatch.setattr(manage, "run", run)
    assert manage.collect(path, action="probe")["host_key"] == "ssh-ed25519 public-fixture"
    assert calls == ["probe"]


def test_local_config_must_be_private(tmp_path: Path) -> None:
    path = config(tmp_path / "connection.json", {"username": "collector"})
    path.chmod(0o644)
    with pytest.raises(ValueError, match="Owner-only"):
        manage.private_json(path)


def test_local_inventory_output_is_private_and_refuses_symlinks(tmp_path: Path) -> None:
    path = tmp_path / "inventory.json"
    manage.save(path, {"fixture": "content"})
    assert path.stat().st_mode & 0o777 == 0o600
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    with pytest.raises(ValueError, match="Symlink"):
        manage.save(alias, {"fixture": "changed"})
    assert json.loads(path.read_text()) == {"fixture": "content"}


def test_parallel_uploads_keep_one_private_immutable_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_root: Path,
) -> None:
    document = json.loads(
        (repository_root / "contracts/inventory/examples-v1.2/valid-discovery.json").read_text()
    )
    document["captured_at"] = datetime.now(UTC).isoformat()
    raw = (json.dumps(document, indent=2) + "\n").encode()
    identity = str(uuid4())
    receipt = {
        "submission_id": str(uuid4()),
        "inventory_id": document["inventory_id"],
        "server_id": identity,
        "status": "accepted",
        "duplicate": False,
        "source": "ansible_api",
        "received_at": datetime.now(UTC).isoformat(),
    }
    receipt["status_url"] = "/api/v1/inventories/submissions/" + receipt["submission_id"]
    seen = []

    def request(c: dict[str, Any], path: str, data: bytes, *, key: str) -> dict[str, Any]:
        assert path == "/api/v1/inventories"
        assert data == raw
        seen.append(key)
        return dict(receipt)

    monkeypatch.setattr(submit, "request", request)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(lambda _: submit.submit({"receipt_root": str(tmp_path)}, raw), range(2))
        )
    assert all(item["submission_id"] == receipt["submission_id"] for item in results)
    assert len(set(seen)) == 1
    receipts = list(tmp_path.glob("*/*.receipt.json"))
    assert len(receipts) == 1
    assert receipts[0].stat().st_mode & 0o777 == 0o600
    assert json.loads(receipts[0].read_text())["submission_id"] == receipt["submission_id"]
