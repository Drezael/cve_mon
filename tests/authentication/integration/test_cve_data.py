"""Real PostgreSQL queueing, least privilege and successful-import freshness."""

import asyncio
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from scripts.cve_importer.manage import directory
from scripts.security.manage import origin
from tests.authentication.integration.conftest import Browser, Lab
from tests.infrastructure.client import request

pytestmark = pytest.mark.authentication
BASE = "/api/v1/dashboard/cve-data"


async def test_status_and_idempotent_update(browser: Browser) -> None:
    from cve_importer.contracts import Configuration

    from scripts.database import manage as db

    path = directory(browser.lab.config) / "sources.json"
    path.write_text(Configuration().model_dump_json())
    browser.client._transport.app.state.cve_configuration_file = path  # type: ignore[attr-defined]
    assert (await browser.login("initial-admin", browser.lab.bootstrap_password)).status_code == 200
    status = (await browser.client.get(BASE)).json()
    assert status["last_success_at"] is None and status["record_count"] == 0
    assert status["can_update"] and len(status["sources"]) == 1
    key = str(uuid4())
    headers = {"x-csrf-token": browser.csrf, "Idempotency-Key": key}
    assert (
        await browser.client.post(BASE + "/refresh", headers={"Idempotency-Key": key})
    ).status_code == 403
    first, second = await asyncio.gather(
        browser.client.post(BASE + "/refresh", headers=headers),
        browser.client.post(BASE + "/refresh", headers=headers),
    )
    assert first.status_code == second.status_code == 202, first.text
    assert first.json() == second.json() and len(first.json()["jobs"]) == 1
    third = await browser.client.post(
        BASE + "/refresh", headers={**headers, "Idempotency-Key": str(uuid4())}
    )
    assert third.status_code == 202 and third.json() != first.json()
    with browser.lab.owner() as s:
        assert not s.execute("SELECT 1 FROM cve.import_runs").fetchone()
        s.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
    for _ in range(64):
        with db.connect(browser.lab.config, "workflow_control") as s:
            row = s.execute(
                "SELECT automation.n8n_claim('api-fixture','cve-control-queue') v"
            ).fetchone()
            assert row
            item = row["v"]
            if item["kind"] == "empty":
                break
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,'api-fixture','cve-control-queue')",
                (item["id"], item["lease_token"], item["kind"]),
            )
    with browser.lab.owner() as s:
        assert s.execute("SELECT count(*) AS n FROM cve.import_runs").fetchone()["n"] == 1
        s.execute(
            "UPDATE cve.import_runs SET "
            "status='completed',finished_at='2026-10-01T12:00:00Z' WHERE "
            "source_id='cve_list'"
        )
        s.execute("UPDATE automation.workflow_settings SET enabled=false")
    browser.client._transport.app.state.cve_data_cache.invalidate()  # type: ignore[attr-defined]
    status = (await browser.client.get(BASE)).json()
    assert status["last_success_at"].startswith("2026-10-01T12:00:00")
    assert (await browser.client.post(BASE + "/refresh", headers=headers)).json() == first.json()


async def test_viewer_cannot_refresh_and_permissions_are_fresh(browser: Browser) -> None:
    uid, name, password = await browser.user()
    with browser.lab.owner() as conn:
        conn.execute(
            "INSERT INTO security.user_roles(user_id,role_id) SELECT %s,id "
            "FROM security.roles WHERE code='viewer'",
            (uid,),
        )
    assert (await browser.login(name, password)).status_code == 200
    assert (await browser.client.get(BASE)).status_code == 200
    assert not (await browser.client.get(BASE)).json()["can_update"]
    response = await browser.client.post(
        BASE + "/refresh", headers={"x-csrf-token": browser.csrf, "Idempotency-Key": str(uuid4())}
    )
    assert response.status_code == 403
    with browser.lab.owner() as conn:
        conn.execute("DELETE FROM security.user_roles WHERE user_id=%s", (uid,))
    assert (await browser.client.get(BASE)).status_code == 403
    assert (await browser.client.get(BASE + "/documents")).status_code == 403
    assert (await browser.client.get(BASE + "/documents/CVE-2026-12345")).status_code == 403


async def test_refresh_fails_closed_without_configuration(browser: Browser) -> None:
    browser.client._transport.app.state.cve_configuration_file = None  # type: ignore[attr-defined]
    assert (await browser.login("initial-admin", browser.lab.bootstrap_password)).status_code == 200
    status = await browser.client.get(BASE)
    assert status.status_code == 200 and not status.json()["can_update"]
    response = await browser.client.post(
        BASE + "/refresh",
        headers={"x-csrf-token": browser.csrf, "Idempotency-Key": str(uuid4())},
    )
    assert response.status_code == 503


def test_native_ingress_forwards_both_routes(auth_lab: Lab) -> None:
    assert request(auth_lab.config, path=BASE).status == 401
    response = request(
        auth_lab.config,
        path=BASE + "/refresh",
        method="POST",
        headers={"Origin": origin(auth_lab.config), "Idempotency-Key": str(uuid4())},
    )
    assert response.status == 403
    assert '"code":"FORBIDDEN"' in response.body


async def test_failed_import_resumes_its_checkpoint(browser: Browser) -> None:
    from scripts.database import manage as db

    app = browser.client._transport.app  # type: ignore[attr-defined]
    app.state.cve_configuration_file = directory(browser.lab.config) / "sources.json"
    assert (await browser.login("initial-admin", browser.lab.bootstrap_password)).status_code == 200
    with browser.lab.owner() as conn:
        original = conn.execute(
            "SELECT r.id,r.job_id,r.created_at FROM cve.import_runs r "
            "JOIN cve.source_leases l ON l.active_run=r.id WHERE l.source_id='cve_list'"
        ).fetchone()
        assert original
        conn.execute(
            "UPDATE cve.import_runs SET status='failed',"
            "progress=jsonb_build_object('checkpoint',2000) WHERE id=%s",
            (original["id"],),
        )
        conn.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
    with db.connect(browser.lab.config, "api_security") as conn:
        conn.execute("SELECT automation.control_job(%s,'cancel')", (original["job_id"],))
    response = await browser.client.post(
        BASE + "/refresh", headers={"x-csrf-token": browser.csrf, "Idempotency-Key": str(uuid4())}
    )
    assert response.status_code == 202, response.text
    for _ in range(64):
        with db.connect(browser.lab.config, "workflow_control") as conn:
            row = conn.execute(
                "SELECT automation.n8n_claim('resume-fixture','cve-control-queue') v"
            ).fetchone()
            assert row
            item = row["v"]
            conn.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,'resume-fixture','cve-control-queue')",
                (item["id"], item["lease_token"], item["kind"]),
            )
        if item["kind"] == "command":
            break
    else:
        raise AssertionError("Resume command never reached n8n")
    with browser.lab.owner() as conn:
        current = conn.execute(
            "SELECT id,job_id,created_at,status,progress FROM cve.import_runs WHERE id=%s",
            (original["id"],),
        ).fetchone()
        assert (
            current
            and current["job_id"] != original["job_id"]
            and current["created_at"] == original["created_at"]
        )
        assert current["status"] == "planned" and current["progress"] == {"checkpoint": 2000}
        conn.execute("UPDATE automation.workflow_settings SET enabled=false")


async def test_pipeline_counts_distinguish_records_and_job_states(browser: Browser) -> None:
    from scripts.database import manage as db

    assert (await browser.login("initial-admin", browser.lab.bootstrap_password)).status_code == 200
    before = (await browser.client.get(BASE)).json()["pipeline"]
    success = None
    with browser.lab.owner() as conn:
        for state in [
            "pending",
            "queued",
            "running",
            "retry_pending",
            "succeeded",
            "failed",
            "timed_out",
            "cancelled",
        ]:
            row = conn.execute(
                "INSERT INTO automation.jobs(job_type,status,runtime_version,creator_role,"
                "request_fingerprint,correlation_id,idempotency_key,lease_owner,lease_token,"
                "lease_until) "
                "VALUES('cve.enrich.record',%s,1,'api_security',sha256('pipeline'::bytea),"
                "gen_random_uuid(),%s,CASE WHEN %s='running' THEN gen_random_uuid() END,"
                "CASE WHEN %s='running' THEN gen_random_uuid() END,"
                "CASE WHEN %s='running' THEN clock_timestamp()+interval '1 minute' END) "
                "RETURNING id",
                (state, uuid4().hex, state, state, state),
            ).fetchone()
            if state == "succeeded":
                assert row
                success = row["id"]
        conn.execute(
            "INSERT INTO automation.jobs(job_type,idempotency_key,runtime_version,creator_role,"
            "request_fingerprint,correlation_id) VALUES('inventory.process',%s,1,'api_ingest',"
            "sha256('foreign'::bytea),gen_random_uuid())",
            (uuid4().hex,),
        )
        for identity, kind in [("CVE-2099-800001", "cve"), ("OSV-pipeline-check", "advisory")]:
            revision = uuid4()
            conn.execute(
                "INSERT INTO cve.enrichment_identities(identity,kind) VALUES(%s,%s)",
                (identity, kind),
            )
            conn.execute(
                "INSERT INTO cve.enrichment_revisions(id,identity,rule_version,"
                "input_fingerprint,result,job_id) "
                "VALUES(%s,%s,'enrichment-1',sha256('pipeline'::bytea),'{}'::jsonb,%s)",
                (revision, identity, success),
            )
            conn.execute(
                "UPDATE cve.enrichment_identities SET current_revision_id=%s,current_version=1 "
                "WHERE identity=%s",
                (revision, identity),
            )
        conn.execute(
            "INSERT INTO cve.enrichment_identities(identity,kind) VALUES('CVE-2099-800003','cve')"
        )
    browser.client._transport.app.state.cve_data_cache.invalidate()  # type: ignore[attr-defined]
    response = await browser.client.get(BASE)
    assert response.status_code == 200, response.text
    after = response.json()["pipeline"]
    for field, delta in {
        "waiting": 2,
        "running": 1,
        "retrying": 1,
        "outstanding": 4,
        "completed_jobs": 1,
        "failed_jobs": 2,
        "processed_records": 2,
        "processed_cves": 1,
        "processed_advisories": 1,
    }.items():
        assert after[field] - before[field] == delta, field
    assert after["outstanding"] == after["waiting"] + after["running"] + after["retrying"]
    assert after["processed_records"] == after["processed_cves"] + after["processed_advisories"]
    assert response.json()["record_count"] == 0  # No fabricated download count from jobs.
    import psycopg

    with db.connect(browser.lab.config, "api_reader") as conn, pytest.raises(psycopg.Error):
        conn.execute("SELECT cve.dashboard_pipeline_status()")


def test_status_sample_uses_bounded_queue_head(auth_lab: Lab) -> None:
    from scripts.database import manage as db

    with auth_lab.owner() as conn:
        conn.execute(
            "INSERT INTO automation.jobs(job_type,runtime_version,creator_role,request_fingerprint,"
            "correlation_id,idempotency_key,status,scheduled_at) "
            "SELECT 'cve.enrich.reconcile',1,'api_security',sha256(g::text::bytea),"
            "gen_random_uuid(),'monitoring-load-'||g,'queued',clock_timestamp() "
            "FROM generate_series(1,120000) g"
        )
        conn.execute("ANALYZE automation.jobs")
    with db.connect(auth_lab.config, "status_probe") as conn:
        conn.execute("SET LOCAL statement_timeout='2s'")
        data = conn.execute("SELECT status.sample() value").fetchone()
        assert data and data["value"]["schema_ready"] and data["value"]["capped"]
    with auth_lab.owner() as conn:
        plan = conn.execute(
            "EXPLAIN (FORMAT JSON) SELECT job_type,status,scheduled_at,heartbeat_at,lease_until "
            "FROM automation.jobs WHERE runtime_version=1 AND job_type<>'status.collect' "
            "AND status IN ('queued','retry_pending','running') "
            "ORDER BY scheduled_at,id LIMIT 10001"
        ).fetchone()
        assert plan and "jobs_monitoring_active" in str(plan)


async def test_source_status_prefers_resumed_run_over_newer_cancelled_attempt(
    browser: Browser,
) -> None:
    assert (await browser.login("initial-admin", browser.lab.bootstrap_password)).status_code == 200
    with browser.lab.owner() as conn:
        active = conn.execute(
            "SELECT r.id FROM cve.import_runs r JOIN cve.source_leases l ON l.active_run=r.id "
            "WHERE l.source_id='cve_list'"
        ).fetchone()
        assert active
        conn.execute(
            "INSERT INTO cve.import_runs(source_id,mode,context,request_key,correlation_id,status) "
            "VALUES('cve_list','initial','{}'::jsonb,%s,%s,'cancelled')",
            (uuid4().hex, uuid4()),
        )
    data = (await browser.client.get(BASE)).json()
    source = next(row for row in data["sources"] if row["id"] == "cve_list")
    assert source["updating"] and source["status"] == "planned"


async def test_parallel_same_session_reads_share_stats_and_keep_fresh_permissions(
    browser: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cve_api import cve_data_cache
    from cve_findings.repository import one as original

    calls = 0

    async def read(session: AsyncSession, sql: str, **values: Any) -> dict[str, Any] | None:
        nonlocal calls
        calls += 1
        return await original(session, sql, **values)

    monkeypatch.setattr(cve_data_cache, "one", read)
    assert (await browser.login("initial-admin", browser.lab.bootstrap_password)).status_code == 200
    responses = await asyncio.gather(*(browser.client.get(BASE) for _ in range(16)))
    assert all(r.status_code == 200 for r in responses)
    assert calls == 1
    assert len({r.json()["pipeline"]["processed_records"] for r in responses}) == 1


async def test_git_only_refresh_does_not_schedule_other_feeds(
    browser: Browser, tmp_path: Any
) -> None:
    from cve_importer.contracts import Configuration

    path = tmp_path / "git-only.json"
    path.write_text(Configuration().model_dump_json())
    browser.client._transport.app.state.cve_configuration_file = path  # type: ignore[attr-defined]
    assert (await browser.login("initial-admin", browser.lab.bootstrap_password)).status_code == 200
    response = await browser.client.post(
        BASE + "/refresh", headers={"x-csrf-token": browser.csrf, "Idempotency-Key": str(uuid4())}
    )
    assert response.status_code == 202
    assert [job["source"] for job in response.json()["jobs"]] == ["cve_list"]
    status = (await browser.client.get(BASE)).json()
    assert [source["id"] for source in status["sources"]] == ["cve_list"]
    assert status["sources"][0]["configured"]
