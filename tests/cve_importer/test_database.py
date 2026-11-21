"""Native migration/authorization and source-specific job scheduling."""

import json
from uuid import UUID, uuid4

import psycopg
import pytest
from cve_importer.contracts import Configuration

from scripts.database import manage as db
from tests.cve_importer.conftest import Lab
from tests.database.helpers import required_row

pytestmark = pytest.mark.cve_importer


def schedule(
    lab: Lab, source: str = "cisa_kev", mode: str = "initial", key: str | None = None
) -> UUID:
    with db.connect(lab.config, "api_security") as c:
        return UUID(
            str(
                required_row(
                    c.execute(
                        "SELECT cve.schedule_import(%s,%s,%s::jsonb,%s,%s) AS id",
                        (
                            source,
                            mode,
                            json.dumps(
                                {
                                    "configuration": Configuration(
                                        osv_ecosystems=["PyPI"], minimum_delay=0
                                    ).model_dump()
                                }
                            ),
                            key or str(uuid4()),
                            uuid4(),
                        ),
                    )
                )["id"]
            )
        )


def test_schema_and_sources(import_lab: Lab) -> None:
    with import_lab.owner() as c:
        assert required_row(c.execute("SELECT count(*) AS n FROM cve.sources"))["n"] == 5
        assert (
            required_row(
                c.execute(
                    "SELECT count(*) AS n FROM automation.job_types WHERE code LIKE 'cve.import.%'"
                )
            )["n"]
            == 5
        )


@pytest.mark.parametrize(
    "table,query",
    [
        ("inventory.servers", "UPDATE inventory.servers SET display_name='forbidden' WHERE false"),
        (
            "inventory.server_groups",
            "UPDATE inventory.server_groups SET name='forbidden' WHERE false",
        ),
        ("security.user_server_access", "DELETE FROM security.user_server_access WHERE false"),
        ("inventory.snapshots", "DELETE FROM inventory.snapshots WHERE false"),
        ("findings.findings", "DELETE FROM findings.findings WHERE false"),
        ("security.api_tokens", "SELECT * FROM security.api_tokens"),
    ],
)
def test_native_permission_denial(import_lab: Lab, table: str, query: str) -> None:
    with (
        db.connect(import_lab.config, "importer") as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute(query)


def test_operator_permission_inspection_without_inventory_usage(
    import_lab: Lab, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import sys

    from scripts.cve_importer import manage

    monkeypatch.setattr(manage, "load_config", lambda: import_lab.config)
    monkeypatch.setattr(sys, "argv", ["cve-importer", "permissions"])
    assert manage.main() == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 5
    assert not any(row["can_insert"] or row["can_update"] or row["can_delete"] for row in rows)
