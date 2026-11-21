"""Real encrypted backup/isolated restore and genuine ENOSPC inside a disposable tmpfs."""

import base64
import json
import os
import time
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

from scripts.database import manage as db
from scripts.hardening.backup import transform
from scripts.infrastructure.manage import Config, compose
from tests.database.conftest import db_config

__all__ = ["db_config"]
pytestmark = pytest.mark.hardening


def test_encrypted_backup_restore_without_plaintext_source(
    db_config: Config, tmp_path: Path
) -> None:
    assert db_config.project.startswith("cve-db-test-")
    with db.connect(db_config, "dashboard_admin") as c:
        server = c.execute(
            "INSERT INTO inventory.servers(display_name,inventory_hostname,inventory_name) "
            "VALUES('phase23-restore','restore.invalid','synthetic') RETURNING id"
        ).fetchone()
        assert server
    began = time.monotonic()
    source = db.backup(db_config, tmp_path / "original")
    key = tmp_path / "separate-key"
    key.write_bytes(base64.b64encode(os.urandom(32)))
    key.chmod(0o600)
    encrypted = tmp_path / "encrypted"
    encrypted.mkdir(mode=0o700)
    restored = tmp_path / "restored"
    restored.mkdir(mode=0o700)
    for path in source.iterdir():
        transform(path, encrypted / path.name, key)
        path.unlink()
    source.rmdir()
    for path in encrypted.iterdir():
        transform(path, restored / path.name, key, decrypt=True)
    result = db.restore_test(db_config, restored)
    elapsed = time.monotonic() - began
    assert result["schemas"] >= 8
    report = {
        "encrypted_files": len(list(encrypted.iterdir())),
        "restore_verified": True,
        "source_plaintext_removed": True,
        "elapsed_seconds": elapsed,
        "rpo": "point-in-time logical DB dumps; no PITR/WAL archive configured",
        "rto": "measured local small fixture only; excludes incident detection and key retrieval",
    }
    Path(".runtime/test-reports/phase-23-recovery.json").write_text(json.dumps(report, indent=2))


def test_real_database_disk_full_rolls_back_without_host_disk_fill(db_config: Config) -> None:
    assert db_config.project.startswith("cve-db-test-")
    name = "phase23_" + uuid4().hex[:10]
    location = "/tmp/" + name
    compose(db_config, ["exec", "-T", "--user", "postgres", "cve-postgres", "mkdir", location])
    with db.connect(db_config, autocommit=True) as c:
        c.execute("CREATE TABLESPACE " + name + " LOCATION '" + location + "'")
        try:
            c.execute("CREATE TABLE public." + name + "(payload text) TABLESPACE " + name)
            c.execute("ALTER TABLE public." + name + " ALTER COLUMN payload SET STORAGE EXTERNAL")
            with pytest.raises(psycopg.errors.DiskFull):
                c.execute(
                    "INSERT INTO public."
                    + name
                    + " SELECT repeat(md5(g::text),32) FROM generate_series(1,100000) g"
                )
            row = c.execute("SELECT count(*) AS n FROM public." + name).fetchone()
            assert row and row["n"] == 0
            row = c.execute("SELECT 1 AS n").fetchone()
            assert row and row["n"] == 1
        finally:
            c.execute("DROP TABLE IF EXISTS public." + name)
            c.execute("DROP TABLESPACE " + name)
    compose(db_config, ["exec", "-T", "--user", "postgres", "cve-postgres", "rmdir", location])
