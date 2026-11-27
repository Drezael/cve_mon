"""Native roles, fenced workers, immutable inputs and bidirectional candidate selection."""

import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from cve_common.database.engine import Database
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker
from cve_matcher.contracts import Request, Settings
from cve_matcher.service import Service

from scripts.cve_matcher import manage
from scripts.database import manage as db
from tests.cve_enricher.test_native import Env
from tests.cve_importer.conftest import Lab
from tests.inventory_processor.test_processing import drain, submit
from tests.inventory_upload.integration.conftest import Browser
from tests.matching.test_engine import assertion, enrichment, osv_value

pytestmark = pytest.mark.matching


class Harness:
    def __init__(self, browser: Browser) -> None:
        self.browser = browser
        self.database = Database(
            browser.lab.database("matcher").model_copy(update={"statement_timeout_ms": 30000})
        )
        self.database.open()
        self.service = Service(self.database)
        self.repository = JobRepository(self.database, self.service.registry())

    async def execute(self) -> Any:
        job = await self.repository.claim(uuid4(), 30)
        if job is None:
            return None
        context = ExecutionContext(
            self.repository, job, self.repository.registry.get(job.job_type, 1), asyncio.Event()
        )
        return await self.service.handle(context, Request.model_validate(job.payload))

    async def drain(self) -> None:
        for _ in range(1000):
            if await self.execute() is None:
                from tests.application.settle import pending

                if not pending(self.browser, self.repository.registry.names):
                    return
                await asyncio.sleep(0.05)
        raise AssertionError("Unexpected unbounded matching queue")

    def seed(self, identity: str | None = None, *, affected: bool = True) -> tuple[str, UUID]:
        identity = identity or "CVE-2026-" + str(uuid4().int >> 96)
        value = enrichment(
            assertion(
                "osv_package",
                osv_value(
                    package={"ecosystem": "Ubuntu:24.04:LTS", "name": "apache2"},
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1:2.4.58-1ubuntu8.9"}],
                        }
                    ],
                ),
            )
        )
        if not affected:
            value["lifecycle"] = {"value": "rejected"}
        revision = uuid4()
        with self.browser.lab.owner() as c:
            c.execute(
                (
                    "INSERT INTO cve.enrichment_identities(identity,kind) VALUES(%s,'c"
                    "ve') ON CONFLICT DO NOTHING"
                ),
                (identity,),
            )
            source = c.execute(
                "SELECT id FROM cve.source_revisions ORDER BY id LIMIT 1"
            ).fetchone()["id"]
            job = c.execute(
                "SELECT id FROM automation.jobs ORDER BY created_at LIMIT 1"
            ).fetchone()["id"]
            value["affected"][0]["provenance"]["source_revision_id"] = str(source)
            c.execute(
                (
                    "INSERT INTO cve.enrichment_revisions(id,identity,rule_version,inp"
                    "ut_fingerprint,result,job_id) VALUES(%s,%s,'enrichment-1',%s,%s::"
                    "jsonb,%s)"
                ),
                (
                    revision,
                    identity,
                    hashlib.sha256(str(revision).encode()).digest(),
                    json.dumps(value),
                    job,
                ),
            )
            c.execute("INSERT INTO cve.enrichment_inputs VALUES(%s,%s)", (revision, source))
            c.execute(
                (
                    "UPDATE cve.enrichment_identities SET current_revision_id=%s,curre"
                    "nt_version=current_version+1 WHERE identity=%s"
                ),
                (revision, identity),
            )
        return identity, revision

    async def snapshot(self) -> UUID:
        from tests.inventory_processor.test_normalization import sample

        value = sample()
        value["packages"]["items"][0]["source_package"] = {
            "name": "apache2",
            "version": value["packages"]["items"][0]["version"],
        }
        receipt, _ = await submit(self.browser, value)
        await drain(self.browser)
        with self.browser.lab.owner() as c:
            return UUID(
                str(
                    c.execute(
                        (
                            "SELECT snapshot_id FROM inventory.processing_status WHERE submiss"
                            "ion_id=%s"
                        ),
                        (receipt["submission_id"],),
                    ).fetchone()["snapshot_id"]
                )
            )

    def enqueue(self, kind: str, **values: Any) -> str:
        return manage.enqueue(self.browser.lab.config, kind, Request.model_validate(values))


@pytest.fixture
async def harness(browser: Browser, tmp_path: Path) -> Any:
    with browser.lab.owner() as c:
        seeded = c.execute("SELECT 1 FROM cve.source_revisions LIMIT 1").fetchone()
    if not seeded:
        env = Env(Lab(browser.lab.config), tmp_path / "initial")
        try:
            await env.importer.run("cve_list")
            await env.drain()
        finally:
            await env.importer.transport.close()
            await env.importer.database.close()
            await env.pipeline.close()
            await env.client.close()
            await env.database.close()
    value = Harness(browser)
    try:
        await value.drain()
        yield value
    finally:
        await value.database.close()


async def test_e2e_acceptance_snapshot_enrichment_match_outbox(
    harness: Harness, tmp_path: Path
) -> None:
    snapshot = await harness.snapshot()
    env = Env(Lab(harness.browser.lab.config), tmp_path)
    try:
        env.importer.wire.osv[0]["aliases"] = ["CVE-2026-12345"]
        env.importer.wire.osv[0]["affected"] = [
            osv_value(
                package={"ecosystem": "Ubuntu:24.04:LTS", "name": "apache2"},
                ranges=[
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1:2.4.58-1ubuntu8.9"}],
                    }
                ],
            )
        ]
        for source in ["cve_list", "nvd", "ubuntu", "cisa_kev", "osv"]:
            await env.importer.run(source)
        await env.drain()
        await harness.drain()
        with harness.browser.lab.owner() as c:
            row = c.execute(
                (
                    "SELECT * FROM matching.current_evaluations WHERE identity='CVE-20"
                    "26-12345' AND snapshot_id=%s"
                ),
                (snapshot,),
            ).fetchone()
            assert row and row["status"] == "affected" and row["is_current"]
            assert row["result"]["components"][0]["evidence"][0]["provenance"]["source_revision_id"]
            assert c.execute("SELECT count(*) n FROM findings.findings").fetchone()["n"] == 0
            assert (
                c.execute(
                    "SELECT count(*) n FROM automation.event_outbox WHERE event_type='"
                    "matching.affected_confirmed'"
                ).fetchone()["n"]
                > 0
            )
            revision = row["enrichment_revision_id"]
            before = c.execute(
                "SELECT to_jsonb(s) v FROM inventory.snapshots s WHERE id=%s", (snapshot,)
            ).fetchone()
        harness.enqueue(
            "evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=revision
        )
        await harness.drain()
        with harness.browser.lab.owner() as c:
            assert (
                c.execute(
                    (
                        "SELECT count(*) n FROM matching.result_revisions WHERE snapshot_i"
                        "d=%s AND identity='CVE-2026-12345'"
                    ),
                    (snapshot,),
                ).fetchone()["n"]
                == 1
            )
            assert (
                c.execute(
                    "SELECT to_jsonb(s) v FROM inventory.snapshots s WHERE id=%s", (snapshot,)
                ).fetchone()
                == before
            )
    finally:
        await env.importer.transport.close()
        await env.importer.database.close()
        await env.pipeline.close()
        await env.client.close()
        await env.database.close()


async def test_bidirectional_candidates_and_rejection(harness: Harness) -> None:
    snapshot = await harness.snapshot()
    identity, revision = harness.seed()
    harness.enqueue("evaluate_vulnerability", enrichment_revision_id=revision)
    await harness.drain()
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                (
                    "SELECT status FROM matching.current_evaluations WHERE identity=%s"
                    " AND snapshot_id=%s"
                ),
                (identity, snapshot),
            ).fetchone()["status"]
            == "affected"
        )
    _, rejected = harness.seed(identity, affected=False)
    harness.enqueue("evaluate_vulnerability", enrichment_revision_id=rejected)
    await harness.drain()
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                (
                    "SELECT status FROM matching.current_evaluations WHERE identity=%s"
                    " AND snapshot_id=%s"
                ),
                (identity, snapshot),
            ).fetchone()["status"]
            == "not_applicable"
        )
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM matching.result_revisions WHERE identity=%"
                    "s AND snapshot_id=%s"
                ),
                (identity, snapshot),
            ).fetchone()["n"]
            == 2
        )


@pytest.mark.parametrize("workers", [2, 4])
async def test_concurrency_idempotency(harness: Harness, workers: int) -> None:
    snapshot = await harness.snapshot()
    identity, revision = harness.seed()
    await harness.drain()
    for _ in range(workers):
        harness.enqueue(
            "evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=revision
        )
    await asyncio.gather(*(harness.execute() for _ in range(workers)))
    await harness.drain()
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM matching.result_revisions WHERE identity=%"
                    "s AND snapshot_id=%s"
                ),
                (identity, snapshot),
            ).fetchone()["n"]
            == 1
        )
        assert (
            c.execute(
                (
                    "SELECT current_version FROM matching.current_evaluations WHERE id"
                    "entity=%s AND snapshot_id=%s"
                ),
                (identity, snapshot),
            ).fetchone()["current_version"]
            == 1
        )


async def test_stale_enrichment_cannot_publish(harness: Harness) -> None:
    snapshot = await harness.snapshot()
    identity, old = harness.seed()
    _, new = harness.seed(identity, affected=False)
    harness.enqueue("evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=new)
    await harness.drain()
    harness.enqueue("evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=old)
    await harness.drain()
    with harness.browser.lab.owner() as c:
        row = c.execute(
            (
                "SELECT enrichment_revision_id,status FROM matching.current_evalua"
                "tions WHERE identity=%s AND snapshot_id=%s"
            ),
            (identity, snapshot),
        ).fetchone()
        assert row["enrichment_revision_id"] == new and row["status"] == "not_applicable"
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM matching.result_revisions WHERE identity=%"
                    "s AND snapshot_id=%s"
                ),
                (identity, snapshot),
            ).fetchone()["n"]
            == 2
        )


@pytest.mark.parametrize(
    "table",
    [
        "inventory.servers",
        "inventory.server_groups",
        "inventory.packages",
        "inventory.snapshots",
        "cve.source_records",
        "cve.enrichment_revisions",
        "security.users",
        "security.api_tokens",
        "findings.findings",
        "matching.results",
        "matching.current_results",
    ],
)
async def test_permissions_no_foreign_writes(harness: Harness, table: str) -> None:
    with harness.browser.lab.owner() as c:
        row = c.execute(
            (
                "SELECT has_table_privilege('matcher',%s,'INSERT') i,has_table_pri"
                "vilege('matcher',%s,'UPDATE') u,has_table_privilege('matcher',%s,"
                "'DELETE') d"
            ),
            (table, table, table),
        ).fetchone()
        assert row is not None and not any(row.values())
    with (
        pytest.raises(psycopg.errors.InsufficientPrivilege),
        db.connect(harness.browser.lab.config, "matcher") as c,
    ):
        c.execute("DELETE FROM " + table + " WHERE false")


async def test_immutability_and_restart_recovery(harness: Harness) -> None:
    snapshot = await harness.snapshot()
    identity, revision = harness.seed()
    harness.enqueue(
        "evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=revision
    )
    await harness.drain()
    with harness.browser.lab.owner() as c:
        result = c.execute(
            "SELECT id FROM matching.current_evaluations WHERE identity=%s AND snapshot_id=%s",
            (identity, snapshot),
        ).fetchone()["id"]
    with (
        pytest.raises(psycopg.errors.InsufficientPrivilege),
        db.connect(harness.browser.lab.config, "matcher") as c,
    ):
        c.execute(
            "UPDATE matching.result_revisions SET status='not_affected' WHERE id=%s", (result,)
        )
    with pytest.raises(psycopg.errors.InsufficientPrivilege), harness.browser.lab.owner() as c:
        c.execute(
            "UPDATE matching.result_revisions SET status='not_affected' WHERE id=%s", (result,)
        )
    harness.enqueue(
        "evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=revision
    )
    job = await harness.repository.claim(uuid4(), 0.2)
    assert job
    await asyncio.sleep(0.3)
    await harness.repository.recover()
    await harness.drain()
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM matching.result_revisions WHERE identity=%"
                    "s AND snapshot_id=%s"
                ),
                (identity, snapshot),
            ).fetchone()["n"]
            == 1
        )


async def test_metrics_and_no_startup_backfill(harness: Harness, tmp_path: Path) -> None:
    with db.connect(harness.browser.lab.config, "matcher") as c:
        row = c.execute("SELECT matching.metrics() m").fetchone()
        assert row is not None
        metrics = row["m"]
        assert {
            "candidates",
            "statuses",
            "retry_count",
            "duration_ms",
            "active_workers",
            "unmapped",
            "stale",
        } <= set(metrics)
    settings = Settings(
        app_env="test",
        database=harness.browser.lab.database("matcher"),
        guard_proof_file=tmp_path / "missing",
    )
    worker = Worker(harness.repository, settings)
    assert not worker.active


async def test_performance_indexed_backfill(harness: Harness, record_property: Any) -> None:
    snapshot = await harness.snapshot()
    for _ in range(100):
        harness.seed()
    start = time.monotonic()
    harness.enqueue("backfill")
    await harness.drain()
    duration = time.monotonic() - start
    record_property("matching_100_cves_seconds", duration)
    assert duration < 120
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT count(*) n FROM matching.current_evaluations WHERE snapshot_id=%s",
                (snapshot,),
            ).fetchone()["n"]
            >= 100
        )
        c.execute("SET LOCAL enable_seqscan=off")
        plan = c.execute(
            "EXPLAIN SELECT * FROM matching.vulnerability_keys WHERE key='osv-"
            "source:Ubuntu:apache2'"
        ).fetchall()
        assert "Index" in str(plan) or "Bitmap" in str(plan)


async def test_lost_lease_rolls_back_entire_result(harness: Harness) -> None:
    from cve_common.jobs.errors import LeaseLost

    snapshot = await harness.snapshot()
    identity, revision = harness.seed()
    await harness.drain()
    harness.enqueue(
        "evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=revision
    )
    job = await harness.repository.claim(uuid4(), 0.2)
    assert job
    context = ExecutionContext(
        harness.repository, job, harness.repository.registry.get(job.job_type, 1), asyncio.Event()
    )
    await asyncio.sleep(0.3)
    with pytest.raises(LeaseLost):
        await harness.service.handle(context, Request.model_validate(job.payload))
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM matching.result_revisions WHERE identity=%"
                    "s AND snapshot_id=%s"
                ),
                (identity, snapshot),
            ).fetchone()["n"]
            == 0
        )
    await harness.repository.recover()


async def test_old_snapshot_kept_historical(harness: Harness) -> None:
    from tests.inventory_processor.test_normalization import sample
    from tests.inventory_upload.integration.conftest import provision, technical

    upload = await provision(harness.browser)
    value = sample()
    value["server_id"] = upload.server["id"]
    snapshots = []
    for _ in range(2):
        value["inventory_id"] = str(uuid4())
        response = await technical(harness.browser, upload, json.dumps(value).encode())
        assert response.status_code == 202
        await drain(harness.browser)
        with harness.browser.lab.owner() as c:
            snapshots.append(
                c.execute(
                    "SELECT snapshot_id FROM inventory.processing_status WHERE submission_id=%s",
                    (response.json()["submission_id"],),
                ).fetchone()["snapshot_id"]
            )
        from datetime import UTC, datetime

        value["captured_at"] = datetime.now(UTC).isoformat()
    identity, revision = harness.seed()
    await harness.drain()
    harness.enqueue(
        "evaluate_candidate_batch", snapshot_id=snapshots[1], enrichment_revision_id=revision
    )
    await harness.drain()
    harness.enqueue(
        "evaluate_candidate_batch", snapshot_id=snapshots[0], enrichment_revision_id=revision
    )
    await harness.drain()
    with harness.browser.lab.owner() as c:
        row = c.execute(
            (
                "SELECT snapshot_id FROM matching.current_evaluations WHERE server"
                "_id=%s AND identity=%s"
            ),
            (upload.server["id"], identity),
        ).fetchone()
        assert row["snapshot_id"] == snapshots[1]
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM matching.result_revisions WHERE server_id="
                    "%s AND identity=%s"
                ),
                (upload.server["id"], identity),
            ).fetchone()["n"]
            == 2
        )


async def test_input_republication_a_b_a(harness: Harness) -> None:
    snapshot = await harness.snapshot()
    identity, a = harness.seed()
    await harness.drain()
    for revision in [a, harness.seed(identity, affected=False)[1], a]:
        with harness.browser.lab.owner() as c:
            c.execute(
                (
                    "UPDATE cve.enrichment_identities SET current_revision_id=%s,curre"
                    "nt_version=current_version+1 WHERE identity=%s"
                ),
                (revision, identity),
            )
        harness.enqueue(
            "evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=revision
        )
        await harness.drain()
    with harness.browser.lab.owner() as c:
        row = c.execute(
            (
                "SELECT current_version,enrichment_revision_id FROM matching.curre"
                "nt_evaluations WHERE identity=%s AND snapshot_id=%s"
            ),
            (identity, snapshot),
        ).fetchone()
        assert row["current_version"] == 3 and row["enrichment_revision_id"] == a
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM matching.result_revisions WHERE identity=%"
                    "s AND snapshot_id=%s"
                ),
                (identity, snapshot),
            ).fetchone()["n"]
            == 2
        )


async def test_sealed_children_and_provenance(harness: Harness) -> None:
    snapshot = await harness.snapshot()
    identity, revision = harness.seed()
    await harness.drain()
    harness.enqueue(
        "evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=revision
    )
    await harness.drain()
    with harness.browser.lab.owner() as c:
        result = c.execute(
            "SELECT id FROM matching.current_evaluations WHERE identity=%s AND snapshot_id=%s",
            (identity, snapshot),
        ).fetchone()["id"]
    for table in ["coverage", "result_evidence", "result_conflicts"]:
        with pytest.raises(psycopg.errors.InsufficientPrivilege), harness.browser.lab.owner() as c:
            if table == "coverage":
                c.execute("INSERT INTO matching.coverage VALUES(%s,'{}')", (result,))
            else:
                c.execute("INSERT INTO matching." + table + " VALUES(%s,999999,'{}')", (result,))
    with pytest.raises(psycopg.errors.CheckViolation), harness.browser.lab.owner() as c:
        clone = uuid4()
        c.execute(
            "INSERT INTO matching.result_revisions SELECT %s,run_id,server_id,"
            "snapshot_id,identity,enrichment_revision_id,rule_version,%s,status,"
            "reason,result,created_at FROM matching.result_revisions WHERE id=%s",
            (clone, hashlib.sha256(str(clone).encode()).digest(), result),
        )
        c.execute(
            "INSERT INTO matching.result_evidence VALUES(%s,0,%s::jsonb)",
            (clone, json.dumps({"provenance": {"source_revision_id": str(uuid4())}})),
        )


@pytest.mark.parametrize("field", ["snapshot_id", "server_id", "enrichment_revision_id"])
async def test_composite_input_foreign_keys(harness: Harness, field: str) -> None:
    snapshot = await harness.snapshot()
    identity, revision = harness.seed()
    await harness.drain()
    harness.enqueue(
        "evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=revision
    )
    await harness.drain()
    with harness.browser.lab.owner() as c:
        result = c.execute(
            "SELECT id FROM matching.current_evaluations WHERE identity=%s AND snapshot_id=%s",
            (identity, snapshot),
        ).fetchone()["id"]
    # Mutate a selected fixture column only; no SQL comes from runtime input.
    columns = [
        "run_id",
        "server_id",
        "snapshot_id",
        "identity",
        "enrichment_revision_id",
        "rule_version",
    ]
    projection = ",".join("CAST(%s AS uuid)" if name == field else name for name in columns)
    with pytest.raises(psycopg.errors.ForeignKeyViolation), harness.browser.lab.owner() as c:
        clone = uuid4()
        c.execute(
            "INSERT INTO matching.result_revisions SELECT %s,"
            + projection
            + ",%s,status,reason,result,created_at FROM matching.result_revisions WHERE id=%s",
            (clone, uuid4(), hashlib.sha256(str(clone).encode()).digest(), result),
        )


async def test_oversized_assertions_rollback_without_result(harness: Harness) -> None:
    from cve_common.jobs.errors import JobError

    identity, revision = harness.seed()
    with harness.browser.lab.owner() as c:
        value = c.execute(
            "SELECT result FROM cve.enrichment_revisions WHERE id=%s", (revision,)
        ).fetchone()["result"]
        value["affected"] *= 4097
        other = uuid4()
        c.execute(
            "INSERT INTO cve.enrichment_revisions SELECT %s,identity,rule_version,"
            "%s,%s::jsonb,created_at,job_id FROM cve.enrichment_revisions WHERE id=%s",
            (other, hashlib.sha256(str(other).encode()).digest(), json.dumps(value), revision),
        )
    harness.enqueue("evaluate_vulnerability", enrichment_revision_id=other)
    job = await harness.repository.claim(uuid4(), 30)
    assert job is not None
    context = ExecutionContext(
        harness.repository, job, harness.repository.registry.get(job.job_type, 1), asyncio.Event()
    )
    with pytest.raises(JobError) as rejected:
        await harness.service.handle(context, Request.model_validate(job.payload))
    # A direct handler call bypasses Worker.execute's failure completion. Finish
    # the rejected job with its fence so subsequent tests do not await a live lease.
    assert await harness.repository.finish(job, "failed", rejected.value.code)
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT count(*) n FROM matching.indexed_revisions WHERE enrichment_revision_id=%s",
                (other,),
            ).fetchone()["n"]
            == 0
        )
        assert (
            c.execute(
                "SELECT count(*) n FROM matching.result_revisions WHERE enrichment_revision_id=%s",
                (other,),
            ).fetchone()["n"]
            == 0
        )


async def test_first_imported_deep_nvd_revision_reaches_native_candidate_lookup(
    harness: Harness, tmp_path: Path
) -> None:
    from tests.cve_importer import fixtures

    snapshot = await harness.snapshot()
    identity = "CVE-2096-" + str(uuid4().int >> 96)
    cpe = "cpe:2.3:a:acme:app:1.0.0:*:*:*:*:*:*:*"
    tree: dict[str, Any] = {
        "operator": "OR",
        "cpeMatch": [{"criteria": cpe, "vulnerable": True, "matchCriteriaId": str(uuid4())}],
    }
    for _ in range(17):
        tree = {"operator": "OR", "cpeMatch": [], "nodes": [tree]}
    # The public host schema does not yet collect CPEs. Seed a native CPE search
    # identity to exercise the real SQL candidate boundary independently of collection.
    with harness.browser.lab.owner() as s:
        s.execute(
            "INSERT INTO matching.inventory_keys(snapshot_id,key) VALUES(%s,%s)",
            (snapshot, "cpe:a:acme:app"),
        )
        assert not s.execute(
            "SELECT 1 FROM matching.current_results WHERE identity=%s", (identity,)
        ).fetchone()
    env = Env(Lab(harness.browser.lab.config), tmp_path / "deep-nvd")
    try:
        env.importer.wire.nvd = [{**fixtures.nvd(identity), "configurations": [tree]}]
        await env.importer.run("nvd")
        await env.drain()
        await harness.drain()
        with harness.browser.lab.owner() as s:
            row = s.execute(
                "SELECT r.id FROM matching.result_revisions r WHERE r.identity=%s "
                "AND r.snapshot_id=%s",
                (identity, snapshot),
            ).fetchone()
            assert row, "The first imported revision must reach evaluation without an older result"
            assert s.execute(
                "SELECT 1 FROM matching.vulnerability_keys k JOIN cve.enrichment_revisions r "
                "ON r.id=k.enrichment_revision_id WHERE r.identity=%s AND k.key='cpe:a:acme:app'",
                (identity,),
            ).fetchone()
    finally:
        await env.importer.transport.close()
        await env.importer.database.close()
        await env.pipeline.close()
        await env.client.close()
        await env.database.close()
