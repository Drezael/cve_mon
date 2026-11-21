"""Verify the existing glibc cluster, builtin application locales and role data on musl."""

import json
from uuid import uuid4

import pytest

from scripts.database import manage as db
from scripts.infrastructure.manage import compose, load_config

pytestmark = pytest.mark.hardening
OLD = "postgres@sha256:f1ea2a1a4fb7b68d4836be1fdcb8a6466a89b072158bf9d97663600538c294c5"


def test_existing_cluster_and_builtin_locale_survive_runtime_change() -> None:
    cfg = load_config(overrides={"COMPOSE_PROJECT_NAME": "cve-db-test-" + uuid4().hex[:12]})
    db.prepare(cfg)
    override = db.workdir(cfg) / "old-runtime.json"
    override.write_text(json.dumps({"services": {"cve-postgres": {"image": OLD}}}))
    try:
        compose(cfg, ["-f", str(override), "up", "-d", "--wait", "cve-postgres"])
        db.provision(cfg)
        db.migrate(cfg)
        with db.connect(cfg) as conn:
            locales = conn.execute(
                "SELECT datname,datlocprovider,datlocale FROM pg_database "
                "WHERE datname IN ('cve_monitoring','n8n') ORDER BY datname"
            ).fetchall()
            assert len(locales) == 2
            assert all(
                r["datlocprovider"] == "b" and r["datlocale"] == "PG_UNICODE_FAST" for r in locales
            )
            conn.execute("CREATE SCHEMA portability")
            conn.execute("CREATE TABLE portability.unicode_values (value text PRIMARY KEY)")
            for value in ["Å", "A", "Ä", "ä", "ö", "ss", "ß", "é", "é", "İ", "𐍈"]:
                conn.execute("INSERT INTO portability.unicode_values VALUES (%s)", (value,))
            before_order = conn.execute(
                "SELECT value FROM portability.unicode_values ORDER BY value"
            ).fetchall()
        before = {name: db.fingerprint(cfg, name) for name in ["cve_monitoring", "n8n"]}
        with db.connect(cfg) as conn:
            roles = conn.execute(
                "SELECT rolname,rolpassword FROM pg_authid ORDER BY rolname"
            ).fetchall()
        compose(cfg, ["stop", "cve-postgres"])
        compose(cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        assert {name: db.fingerprint(cfg, name) for name in before} == before
        with db.connect(cfg) as conn:
            assert (
                conn.execute(
                    "SELECT value FROM portability.unicode_values ORDER BY value"
                ).fetchall()
                == before_order
            )
            assert (
                conn.execute(
                    "SELECT rolname,rolpassword FROM pg_authid ORDER BY rolname"
                ).fetchall()
                == roles
            )
            assert conn.execute("SELECT 1 AS ok").fetchone() == {"ok": 1}
        report = cfg.root / ".runtime/test-reports/phase-23-postgres-portability.json"
        report.write_text(
            json.dumps(
                {
                    "existing_cluster_started": True,
                    "application_fingerprints_equal": True,
                    "unicode_unique_order_equal": True,
                    "role_password_hashes_equal": True,
                    "application_locale": "PG_UNICODE_FAST",
                    "no_password_values_recorded": True,
                },
                indent=2,
            )
        )
    finally:
        db.cleanup_test(cfg)
