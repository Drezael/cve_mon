"""Real PostgreSQL: n8n EPSS commands, single active job, UTC-day scheduling and manual refresh."""

from collections.abc import Iterator
from uuid import uuid4

import pytest
from cve_importer.contracts import Configuration
from psycopg.types.json import Jsonb

from scripts.database import manage as db
from scripts.infrastructure.manage import compose, load_config
from tests.cve_importer.conftest import Lab

pytestmark = pytest.mark.orchestration


@pytest.fixture
def epss_lab() -> Iterator[Lab]:
    cfg = load_config(overrides={"COMPOSE_PROJECT_NAME": "cve-db-test-epss-" + uuid4().hex[:10]})
    db.prepare(cfg)
    try:
        compose(cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        db.provision(cfg)
        db.migrate(cfg)
        yield Lab(cfg)
    finally:
        db.cleanup_test(cfg)


def decide(lab: Lab, queue: str) -> list[dict[str, str]]:
    with db.connect(lab.config, "workflow_control") as s:
        for _ in range(64):
            row = s.execute(
                "SELECT automation.n8n_claim('epss-fixture','cve-control-queue') v"
            ).fetchone()
            assert row and row["v"]["kind"] != "empty"
            item = row["v"]
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,'epss-fixture','cve-control-queue')",
                (item["id"], item["lease_token"], item["kind"]),
            )
            if item["id"] == queue:
                result = s.execute(
                    "SELECT result FROM automation.n8n_queue WHERE id=%s", (queue,)
                ).fetchone()
                assert result
                return list(result["result"])
    raise AssertionError("Queue command not processed")


def command(lab: Lab, cfg: dict[str, object], actor: object = None) -> str:
    request = uuid4()
    if actor:
        with db.connect(lab.config, "api_security") as s:
            row = s.execute(
                "SELECT cve.dashboard_request_update(%s,%s,%s) value", (request, actor, Jsonb(cfg))
            ).fetchone()
            assert row
            return str(row["value"][0]["id"])
    with lab.owner() as s:
        row = s.execute(
            "INSERT INTO "
            "automation.n8n_queue(kind,producer,message_type,payload,"
            "correlation_id,deduplication_key) "
            "VALUES('command','workflow_control','cve.refresh',%s,%s,%s) RETURNING id",
            (Jsonb({"configuration": cfg}), request, str(request)),
        ).fetchone()
        assert row
        return str(row["id"])


def test_n8n_epss_schedule_and_dashboard_command(epss_lab: Lab) -> None:
    cfg = Configuration(enabled=["cve_list", "cisa_kev"], epss_enabled=True).model_dump(mode="json")
    with epss_lab.owner() as s:
        s.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
        actor = s.execute(
            "INSERT INTO security.users(username,email,display_name,status) "
            "VALUES('epsstest','epss@example.test','EPSS','active') RETURNING id"
        ).fetchone()
        assert actor
        s.execute(
            "INSERT INTO security.user_roles(user_id,role_id) SELECT %s,id FROM "
            "security.roles WHERE code='admin'",
            (actor["id"],),
        )
    request = command(epss_lab, cfg, actor["id"])
    with db.connect(epss_lab.config, "workflow_control") as s:
        assert s.execute("SELECT cve.epss_due() due").fetchone() == {"due": True}
    first = decide(epss_lab, request)
    assert {v["source"] for v in first} == {"cve_list", "cisa_kev", "epss"}
    epss = next(v["id"] for v in first if v["source"] == "epss")
    again = decide(epss_lab, command(epss_lab, cfg))
    assert next(v["id"] for v in again if v["source"] == "epss") == epss
    with db.connect(epss_lab.config, "workflow_control") as s:
        assert s.execute("SELECT cve.epss_due() due").fetchone() == {"due": False}
    # Both CVE sources are still active: the periodic tick must still schedule due EPSS.
    with epss_lab.owner() as s:
        s.execute("UPDATE automation.jobs SET status='cancelled' WHERE id=%s", (epss,))
        s.execute(
            "UPDATE automation.workflow_settings SET "
            "auto_updates=true,source_config=%s,next_update_at=clock_timestamp()-interval "
            "'1 minute'",
            (Jsonb(cfg),),
        )
    with db.connect(epss_lab.config, "workflow_control") as s:
        tick = s.execute(
            "SELECT automation.workflow_tick('import','epss-tick','cve-control-import') value"
        ).fetchone()
        assert tick and tick["value"]["scheduled"] is True
    with epss_lab.owner() as s:
        scheduled = s.execute(
            "SELECT id FROM automation.n8n_queue WHERE deduplication_key LIKE "
            "'scheduled-update:%%' ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        assert scheduled
    due = decide(epss_lab, str(scheduled["id"]))
    assert {v["source"] for v in due} == {"cve_list", "cisa_kev", "epss"}
    epss = next(v["id"] for v in due if v["source"] == "epss")
    # A complete current day stops automatic downloads but permits manual corrections.
    with epss_lab.owner() as s:
        s.execute("UPDATE automation.jobs SET status='cancelled' WHERE id=%s", (epss,))
        dataset = s.execute(
            "INSERT INTO "
            "cve.epss_import_runs(score_date,model_version,wire_sha256,source_url) "
            "VALUES((clock_timestamp() AT TIME ZONE "
            "'UTC')::date,'v2026.06.15',decode(repeat('ab',32),'hex'),"
            "'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz') "
            "RETURNING id,score_date,model_version"
        ).fetchone()
        assert dataset
        s.execute(
            "INSERT INTO cve.epss_daily_scores VALUES(%s,'CVE-2026-12345',%s,%s,0.1,0.8)",
            (dataset["id"], dataset["score_date"], dataset["model_version"]),
        )
        s.execute(
            "UPDATE cve.epss_import_runs SET "
            "status='completed',row_count=1,completed_at=clock_timestamp() WHERE id=%s",
            (dataset["id"],),
        )
        s.execute(
            "INSERT INTO cve.epss_current_dataset(singleton,dataset_id) VALUES(true,%s)",
            (dataset["id"],),
        )
    with db.connect(epss_lab.config, "workflow_control") as s:
        assert s.execute("SELECT cve.epss_due() due").fetchone() == {"due": False}
    automatic = decide(epss_lab, command(epss_lab, cfg))
    assert "epss" not in {v["source"] for v in automatic}
    manual = decide(epss_lab, command(epss_lab, cfg, actor["id"]))
    assert "epss" in {v["source"] for v in manual}
