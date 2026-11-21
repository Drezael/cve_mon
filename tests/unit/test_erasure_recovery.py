"""Scope backup cleanup and persist failed erasures without automatic retries."""

import json
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from scripts.automation_executor.agent import (
    abort_unfinished_erasures,
    directory,
    erase,
    fail_erasure,
    prepare,
    purge_managed_backups,
    register_backup,
)
from scripts.infrastructure.manage import load_config


def test_erasure_only_removes_registered_project_backups(tmp_path: Path) -> None:
    config = replace(
        load_config(
            overrides={
                "COMPOSE_PROJECT_NAME": "cve-db-test-purge-unit",
                "MOUNT_BASE": "./.runtime",
                "SECRETS_BASE": "./.runtime",
            }
        ),
        root=tmp_path,
    )
    runtime = tmp_path / ".runtime"
    runtime.mkdir()
    foreign = runtime / "foreign-backup"
    foreign.mkdir()
    (foreign / "manifest.json").write_text(json.dumps({"project": "other-project"}))
    (foreign / "private.enc").write_bytes(b"foreign-data")
    (runtime / "foreign-backup-latest.json").write_text(json.dumps({"backup": str(foreign)}))
    (runtime / "broken-backup-latest.json").write_text("broken")
    malformed = runtime / "foreign-scalar"
    malformed.mkdir()
    (malformed / "manifest.json").write_text("[]")
    (runtime / "scalar-backup-latest.json").write_text(json.dumps({"backup": str(malformed)}))
    own = runtime / "own-backup"
    own.mkdir()
    (own / "private.enc").write_bytes(b"owned-data")
    key = runtime / "own.key"
    key.write_bytes(b"owned-key")
    register_backup(config, own, key)
    assert purge_managed_backups(config) == 1
    assert not own.exists() and not key.exists()
    assert (foreign / "private.enc").read_bytes() == b"foreign-data"
    assert (runtime / "foreign-backup-latest.json").exists()


def test_failed_erasure_is_logged_and_never_retried(tmp_path: Path) -> None:
    config = replace(
        load_config(
            overrides={
                "COMPOSE_PROJECT_NAME": "cve-db-test-purge-unit",
                "MOUNT_BASE": "./.runtime",
                "SECRETS_BASE": "./.runtime",
            }
        ),
        root=tmp_path,
    )
    prepare(config)
    identity = str(uuid4())
    path = directory(config) / ("erase-" + identity + ".json")
    path.write_text(
        json.dumps(
            {
                "phase": "requested",
                "server_id": str(uuid4()),
                "actor_id": str(uuid4()),
                "version": 1,
                "next_attempt_at": 0,
                "retry_count": 3,
            }
        )
    )
    fail_erasure(config, identity, "RESOURCE_BUSY")
    failed = json.loads(path.read_text())
    assert failed["phase"] == "failed" and failed["automatic_retry"] is False
    assert "next_attempt_at" not in failed and "retry_count" not in failed
    before = (directory(config) / "erasure.log").read_text()
    assert "RESOURCE_BUSY" in before and "Datensätze" in before
    abort_unfinished_erasures(config)
    result = erase(config, {**failed, "request_id": identity})
    assert result["status"] == 503
    assert (directory(config) / "erasure.log").read_text() == before


def test_controller_restart_aborts_unfinished_erasure_without_repeating_it(tmp_path: Path) -> None:
    config = replace(
        load_config(
            overrides={
                "COMPOSE_PROJECT_NAME": "cve-db-test-purge-unit",
                "MOUNT_BASE": "./.runtime",
                "SECRETS_BASE": "./.runtime",
            }
        ),
        root=tmp_path,
    )
    prepare(config)
    identity = str(uuid4())
    path = directory(config) / ("erase-" + identity + ".json")
    path.write_text(json.dumps({"phase": "requested", "server_id": str(uuid4())}))
    abort_unfinished_erasures(config)
    value = json.loads(path.read_text())
    assert value["phase"] == "failed" and value["error_code"] == "INTERRUPTED"
    assert value["automatic_retry"] is False
