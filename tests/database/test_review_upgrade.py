"""Safety patches reject a drifted old routine transactionally instead of silently succeeding."""

from collections.abc import Iterator
from uuid import uuid4

import psycopg
import pytest

from scripts.database import manage as db
from scripts.infrastructure.manage import Config, compose
from tests.configuration import load_test_config
from tests.database.helpers import required_row

pytestmark = pytest.mark.database


@pytest.fixture
def upgrade_config() -> Iterator[Config]:
    config = load_test_config(
        overrides={"COMPOSE_PROJECT_NAME": "cve-db-test-review-" + uuid4().hex[:10]}
    )
    db.prepare(config)
    try:
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        db.provision(config)
        db.migrate(config, "00074_manual_server_scan")
        yield config
    finally:
        db.cleanup_test(config)


@pytest.mark.parametrize("drift", [False, True])
def test_vault_upgrade_is_atomic_on_old_definition_drift(
    upgrade_config: Config, drift: bool
) -> None:
    if drift:
        with db.connect(upgrade_config, "cve_migrator") as s:
            s.execute("SET ROLE postgres_owner")
            definition = required_row(
                s.execute(
                    "SELECT pg_get_functiondef('inventory.schedule_ansible(uuid,text,uuid)'"
                    "::regprocedure) AS sql"
                )
            )["sql"]
            original = "AND inventory.ansible_owner_active(p.owner_id)"
            assert definition.count(original) == 1
            s.execute(
                definition.replace(original, "AND (inventory.ansible_owner_active(p.owner_id))"),
                prepare=False,
            )
        with pytest.raises(psycopg.Error, match="Vault schedule patch mismatch"):
            db.migrate(upgrade_config)
    else:
        db.migrate(upgrade_config)
    with db.connect(upgrade_config, "cve_migrator") as s:
        s.execute("SET ROLE postgres_owner")
        revision = required_row(s.execute("SELECT version_num FROM public.alembic_version"))[
            "version_num"
        ]
        assert revision == ("00074_manual_server_scan" if drift else "00077_matching_pep440")
        if drift:
            assert (
                required_row(
                    s.execute("SELECT to_regclass('security.ansible_vaults') AS relation")
                )["relation"]
                is None
            )
