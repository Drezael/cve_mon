"""n8n may schedule V5 and optional KEV, with other external sources still excluded."""

from uuid import uuid4

import psycopg
import pytest
from cve_importer.contracts import Configuration
from psycopg.types.json import Jsonb

from scripts.database import manage as db
from tests.cve_importer.conftest import Lab

pytestmark = pytest.mark.orchestration


def test_n8n_allows_v5_and_kev_but_rejects_other_sources(import_lab: Lab) -> None:
    configuration = Configuration(enabled=["cve_list", "cisa_kev"]).model_dump(mode="json")
    for source in ("cve_list", "cisa_kev"):
        with db.connect(import_lab.config, "workflow_control") as session:
            row = session.execute(
                "SELECT cve.schedule_import(%s,'initial',%s,%s,%s) id",
                (source, Jsonb({"configuration": configuration}), str(uuid4()), uuid4()),
            ).fetchone()
            assert row and row["id"]
            session.rollback()
    for source, changes in (
        ("nvd", {}),
        ("cisa_kev", {"epss_enabled": "true"}),
        ("cisa_kev", {"enabled": ["cve_list", "cisa_kev", "nvd"]}),
        ("cisa_kev", {"cve_list_transport": "release"}),
    ):
        with (
            pytest.raises(psycopg.errors.InsufficientPrivilege),
            db.connect(import_lab.config, "workflow_control") as session,
        ):
            session.execute(
                "SELECT cve.schedule_import(%s,'initial',%s,%s,%s)",
                (
                    source,
                    Jsonb({"configuration": {**configuration, **changes}}),
                    str(uuid4()),
                    uuid4(),
                ),
            )
