"""Upgrade existing groups and memberships to personal ownership without data loss."""

import asyncio
import secrets
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from scripts.database import manage as db
from scripts.infrastructure.manage import (
    compose,
    generate_certificates,
)
from scripts.security import manage as auth
from scripts.services import manage as api
from tests.configuration import load_test_config as load_config

pytestmark = pytest.mark.infrastructure


def test_existing_groups_become_personal_without_losing_memberships(repository_root: Path) -> None:
    project = "cve-db-test-personal-groups-" + uuid4().hex[:10]
    pki = repository_root / ".runtime/personal-group-upgrade-tests" / project / "pki"
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
        db.migrate(config, "00070_default_user_role")
        generate_certificates(config)
        api.prepare(config)
        uid = asyncio.run(
            auth.bootstrap(
                config, "upgrade-admin", "upgrade-admin@example.test", secrets.token_urlsafe(24)
            )
        )
        with db.connect(config, "cve_migrator") as s:
            s.execute("SET ROLE postgres_owner")
            gid, sid = uuid4(), uuid4()
            s.execute(
                "INSERT INTO inventory.server_groups(id,name,created_by) "
                "VALUES(%s,'Existing group',%s)",
                (gid, uid),
            )
            s.execute(
                "INSERT INTO inventory.servers(id,display_name,primary_group_id) "
                "VALUES(%s,'Existing server',%s)",
                (sid, gid),
            )
            s.execute(
                "INSERT INTO inventory.server_group_memberships(server_id,group_id) VALUES(%s,%s)",
                (sid, gid),
            )
        db.migrate(config)
        db.migrate(config)
        with db.connect(config, "cve_migrator") as s:
            s.execute("SET ROLE postgres_owner")
            group = s.execute(
                "SELECT owner_id,name FROM inventory.server_groups WHERE id=%s", (gid,)
            ).fetchone()
            assert group == {"owner_id": UUID(uid), "name": "Existing group"}
            assert s.execute(
                "SELECT primary_group_id FROM inventory.servers WHERE id=%s", (sid,)
            ).fetchone() == {"primary_group_id": None}
            assert s.execute(
                "SELECT 1 n FROM inventory.server_group_memberships "
                "WHERE server_id=%s AND group_id=%s",
                (sid, gid),
            ).fetchone() == {"n": 1}
    finally:
        if created:
            db.cleanup_test(config)
