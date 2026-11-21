"""Actual pre-role deployment upgrade retains the original administrator and credentials."""

import asyncio
import secrets
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.database import manage as db
from scripts.infrastructure.manage import (
    compose,
    generate_certificates,
    load_config,
)
from scripts.security import manage as auth
from scripts.services import manage as api

pytestmark = pytest.mark.infrastructure


def test_existing_administrator_gains_user_during_upgrade(repository_root: Path) -> None:
    project = "cve-db-test-role-upgrade-" + uuid4().hex[:10]
    pki = repository_root / ".runtime/role-upgrade-tests" / project / "pki"
    config = load_config(
        overrides={
            "COMPOSE_PROJECT_NAME": project,
            "TLS_CERT_FILE": str(pki / "server.crt"),
            "TLS_KEY_FILE": str(pki / "server.key"),
            "TLS_TRUST_FILE": str(pki / "server-ca.crt"),
            "CLIENT_CA_FILE": str(pki / "client-ca.crt"),
            "CLIENT_CRL_FILE": str(pki / "client-ca.crl"),
        }
    )
    created = False
    try:
        db.prepare(config)
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "90", "cve-postgres"])
        created = True
        db.provision(config)
        db.migrate(config, "00069_account_locales")
        generate_certificates(config)
        api.prepare(config)
        uid = asyncio.run(
            auth.bootstrap(
                config, "upgrade-admin", "upgrade-admin@example.test", secrets.token_urlsafe(24)
            )
        )
        with db.connect(config, "cve_migrator") as s:
            s.execute("SET ROLE postgres_owner")
            original = s.execute(
                "SELECT password_hash FROM security.password_credentials WHERE user_id=%s", (uid,)
            ).fetchone()
            assert s.execute(
                "SELECT count(*) n FROM security.roles WHERE code='user'"
            ).fetchone() == {"n": 0}
        db.migrate(config)
        db.migrate(config)
        with db.connect(config, "cve_migrator") as s:
            s.execute("SET ROLE postgres_owner")
            assert (
                original
                == s.execute(
                    "SELECT password_hash FROM security.password_credentials WHERE user_id=%s",
                    (uid,),
                ).fetchone()
            )
            assigned = {
                r["code"]
                for r in s.execute(
                    "SELECT r.code FROM security.user_roles a JOIN security.roles r "
                    "ON r.id=a.role_id WHERE a.user_id=%s",
                    (uid,),
                )
            }
            assert assigned == {"admin", "user"}
            audit = s.execute(
                "SELECT technical_principal_id FROM security.audit_log WHERE "
                "action='authorization.admin_user_role_migrated' AND object_id=%s",
                (uid,),
            ).fetchone()
            assert audit and audit["technical_principal_id"]
    finally:
        if created:
            db.cleanup_test(config)
