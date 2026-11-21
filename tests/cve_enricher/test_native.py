"""Importer event to native fenced enrichment, independent EPSS history and strict roles."""

import asyncio
import gzip
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
from cve_common.database.engine import Database
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.repository import JobRepository
from cve_enricher.contracts import Configuration, Request, Result
from cve_enricher.epss import Client
from cve_enricher.pipeline import Pipeline
from cve_enricher.service import Service

from scripts.cve_enricher import manage
from scripts.database import manage as db
from tests.cve_importer.conftest import Lab
from tests.cve_importer.test_pipeline import Harness, wire_response
from tests.database.helpers import required_row

pytestmark = pytest.mark.cve_enricher


class Env:
    def __init__(self, lab: Lab, path: Path) -> None:
        self.lab = lab
        self.importer = Harness(lab, path / "importer")
        self.cfg = Configuration(epss_enabled=True, epss_min_rows=1, batch_size=2)
        manage.prepare(lab.config)
        (manage.directory(lab.config) / "sources.json").write_text(self.cfg.model_dump_json())
        self.database = Database(lab.settings("enricher"))
        self.database.open()
        self.csv = (
            b"#model_version:v2026.06.15,score_date:2026-11-07T12:00:00Z\n"
            b"cve,epss,percentile\n"
            b"CVE-2026-12345,0.123456789,0.987654321\nCVE-2026-12346,0,1\n"
        )
        self.client = Client(
            self.cfg,
            path / "epss",
            client=httpx.AsyncClient(transport=httpx.MockTransport(self.respond)),
        )
        self.pipeline = Pipeline(self.database)
        self.pipeline.start()
        self.service = Service(self.database, self.cfg, self.client, self.pipeline)
        self.repository = JobRepository(self.database, self.service.registry())

    def respond(self, request: httpx.Request) -> httpx.Response:
        return wire_response(
            200,
            content=gzip.compress(self.csv, mtime=0),
            headers={"Content-Type": "application/gzip"},
        )

    async def execute(self) -> Any:
        job = await self.repository.claim(uuid4(), 30)
        if job is None:
            return None
        definition = self.service.registry().get(job.job_type, 1)
        context = ExecutionContext(self.repository, job, definition, asyncio.Event())
        return await self.service.handle(context, Request.model_validate(job.payload))

    async def drain(self) -> None:
        for _ in range(200):
            if await self.execute() is None:
                return
        raise AssertionError("Unexpected unbounded enrichment queue")

    def row(self, identity: str = "CVE-2026-12345") -> dict[str, Any]:
        with self.lab.owner() as c:
            return required_row(
                c.execute("SELECT * FROM cve.current_enrichment WHERE identity=%s", (identity,))
            )


@pytest.fixture
async def env(enrich_lab: Lab, tmp_path: Path) -> AsyncIterator[Env]:
    value = Env(enrich_lab, tmp_path)
    try:
        with enrich_lab.owner() as c:
            seeded = c.execute(
                "SELECT 1 FROM cve.current_enrichment WHERE identity='CVE-2026-12345'"
            ).fetchone()
            epss_seeded = c.execute("SELECT 1 FROM cve.epss_current_dataset").fetchone()
        if not seeded:
            for source in ["cve_list", "nvd", "cisa_kev", "ubuntu", "osv"]:
                await value.importer.run(source)
            await value.drain()
        if not epss_seeded:
            manage.enqueue(enrich_lab.config, "cve.epss.sync_daily")
            await value.drain()
        yield value
    finally:
        await value.importer.transport.close()
        await value.importer.database.close()
        await value.pipeline.close()
        await value.client.close()
        await value.database.close()


async def test_e2e_five_sources_events_revisions_and_epss(env: Env) -> None:
    value = env.importer.wire.cve[0]
    value["containers"]["cna"]["metrics"] = [
        {
            "cvssV3_1": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL",
            }
        }
    ]
    for source in ["cve_list", "nvd", "cisa_kev", "ubuntu", "osv"]:
        await env.importer.run(source)
    await env.drain()
    row = env.row()
    result = row["result"]
    assert result["lifecycle"]["value"] == "published"
    assert result["kev"]["status"] == "present"
    assert any(m["is_preferred"] and m["base_score"] == 9.8 for m in result["cvss"])
    assert {r["source_id"] for r in result["inputs"]} >= {
        "cve_list",
        "nvd",
        "cisa_kev",
        "ubuntu",
        "osv",
    }
    assert any(a["kind"] == "ubuntu_packages" for a in result["affected"])
    assert any(c["kind"] == "multi_cve_advisory" for c in result["conflicts"])
    assert env.row("CVE-2026-12346")["id"] != row["id"]
    job_id = manage.enqueue(env.lab.config, "cve.epss.sync_daily")
    await env.drain()
    assert env.row()["id"] == row["id"]
    with env.lab.owner() as c:
        score = required_row(
            c.execute("SELECT * FROM cve.current_epss_scores WHERE cve_id='CVE-2026-12345'")
        )
        assert str(score["score"]).rstrip("0") == "0.123456789"
        assert str(score["percentile"]).rstrip("0") == "0.987654321"
        assert (
            required_row(c.execute("SELECT status FROM automation.jobs WHERE id=%s", (job_id,)))[
                "status"
            ]
            == "succeeded"
        )
        assert required_row(c.execute("SELECT count(*) AS n FROM inventory.servers"))["n"] == 0
        assert required_row(c.execute("SELECT count(*) AS n FROM findings.findings"))["n"] == 0


async def test_idempotence_and_official_rejection_history(env: Env) -> None:
    previous = env.row()
    manage.enqueue(env.lab.config, "cve.enrich.record", "CVE-2026-12345")
    await env.drain()
    assert env.row()["id"] == previous["id"]
    from tests.cve_importer.fixtures import cve

    env.importer.wire.cve = [cve(state="REJECTED")]
    await env.importer.run("cve_list", "reconcile")
    await env.drain()
    result = env.row()
    assert result["id"] != previous["id"] and result["result"]["lifecycle"]["value"] == "rejected"
    assert not any(v["matching_usable"] for v in result["result"]["affected"])


@pytest.mark.parametrize(
    "query",
    [
        "UPDATE cve.source_revisions SET original_json='{}' WHERE false",
        "UPDATE inventory.servers SET sort_order=0 WHERE false",
        "DELETE FROM inventory.snapshots WHERE false",
        "DELETE FROM security.user_server_access WHERE false",
        "DELETE FROM findings.findings WHERE false",
        "SELECT * FROM security.api_tokens",
    ],
)
def test_native_permission_denials(enrich_lab: Lab, query: str) -> None:
    import psycopg

    with (
        db.connect(enrich_lab.config, "enricher") as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute(query)


async def test_epss_duplicate_day_correction_and_stale_preservation(env: Env) -> None:
    manage.enqueue(env.lab.config, "cve.epss.sync_daily")
    await env.drain()
    with env.lab.owner() as c:
        old = required_row(c.execute("SELECT dataset_id FROM cve.epss_current_dataset"))[
            "dataset_id"
        ]
        revisions = required_row(c.execute("SELECT count(*) AS n FROM cve.enrichment_revisions"))[
            "n"
        ]
    manage.enqueue(env.lab.config, "cve.epss.sync_daily")
    await env.drain()
    with env.lab.owner() as c:
        assert (
            required_row(c.execute("SELECT dataset_id FROM cve.epss_current_dataset"))["dataset_id"]
            == old
        )
    env.csv = env.csv.replace(b"0.123456789", b"0.223456789")
    manage.enqueue(env.lab.config, "cve.epss.sync_daily")
    await env.drain()
    with env.lab.owner() as c:
        changed = required_row(c.execute("SELECT dataset_id FROM cve.epss_current_dataset"))[
            "dataset_id"
        ]
        assert changed != old
        assert (
            required_row(c.execute("SELECT count(*) AS n FROM cve.enrichment_revisions"))["n"]
            == revisions
        )
        assert (
            required_row(
                c.execute(
                    "SELECT count(*) AS n FROM cve.epss_daily_scores WHERE dataset_id=%s", (old,)
                )
            )["n"]
            == 2
        )


async def test_epss_invalid_file_never_replaces_current(env: Env) -> None:
    from cve_enricher.contracts import EnrichmentError

    with env.lab.owner() as c:
        old = required_row(c.execute("SELECT dataset_id FROM cve.epss_current_dataset"))[
            "dataset_id"
        ]
    env.csv = env.csv.replace(b"0.123456789", b"1.2")
    manage.enqueue(env.lab.config, "cve.epss.sync_daily")
    with pytest.raises(EnrichmentError):
        await env.execute()
    with env.lab.owner() as c:
        assert (
            required_row(c.execute("SELECT dataset_id FROM cve.epss_current_dataset"))["dataset_id"]
            == old
        )
    # This direct handler test owns its unfinished lease, so finish it through the native API.
    with env.lab.owner() as c:
        c.execute(
            "UPDATE automation.jobs SET "
            "lease_until=clock_timestamp()-interval '1 second' WHERE "
            "status='running' AND job_type='cve.epss.sync_daily'"
        )
    await env.repository.recover()
    with env.lab.owner() as c:
        c.execute(
            "UPDATE automation.jobs SET "
            "status='failed',lease_owner=NULL,lease_until=NULL,lease_token=NUL"
            "L WHERE job_type='cve.epss.sync_daily' AND status='retry_pending'"
        )


@pytest.mark.parametrize("parallel", [2, 8])
async def test_concurrency_same_identity(env: Env, parallel: int) -> None:
    for _ in range(parallel):
        manage.enqueue(env.lab.config, "cve.enrich.record", "CVE-2026-12345")
    before = env.row()["id"]
    await asyncio.gather(*(env.execute() for _ in range(parallel)))
    assert env.row()["id"] == before


async def test_raw_and_enrichment_immutability(env: Env) -> None:
    import psycopg

    for table in [
        "enrichment_revisions",
        "enrichment_inputs",
        "enrichment_assertions",
        "epss_daily_scores",
    ]:
        with db.connect(env.lab.config, "enricher") as c, pytest.raises(psycopg.Error):
            c.execute("DELETE FROM cve." + table)


async def test_stale_kev_is_unknown_and_read_view_marks_age(env: Env) -> None:
    with env.lab.owner() as c:
        c.execute(
            "UPDATE cve.source_streams SET "
            "last_success_at=clock_timestamp()-interval '8 days' WHERE "
            "source_id='cisa_kev'"
        )
    manage.enqueue(env.lab.config, "cve.enrich.record", "CVE-2026-12345")
    await env.drain()
    value = env.row()
    assert value["kev_status"] == "unknown"
    assert not value["kev_is_current"]


async def test_alias_removal_reprocesses_old_and_new_contexts(env: Env) -> None:
    await env.importer.run("osv", "reconcile")
    await env.drain()
    before = env.row("CVE-2026-12346")
    env.importer.wire.osv[0]["aliases"] = ["CVE-2026-12345"]
    await env.importer.run("osv", "reconcile")
    await env.drain()
    after = env.row("CVE-2026-12346")
    assert after["id"] != before["id"]
    assert not any(r["source_id"] == "osv" for r in after["result"]["inputs"])


async def test_queue_coalesces_pending_identity_without_losing_changes(env: Env) -> None:
    with db.connect(env.lab.config, "enricher") as c:
        first = required_row(
            c.execute(
                "SELECT cve.enqueue_enrichment(%s,%s,%s) AS id",
                ("CVE-2026-12345", str(uuid4()), uuid4()),
            )
        )["id"]
        second = required_row(
            c.execute(
                "SELECT cve.enqueue_enrichment(%s,%s,%s) AS id",
                ("CVE-2026-12345", str(uuid4()), uuid4()),
            )
        )["id"]
        assert first == second
    await env.drain()


async def test_stale_fence_prevents_revision_commit(env: Env) -> None:
    from cve_common.jobs.errors import LeaseLost

    job_id = manage.enqueue(env.lab.config, "cve.enrich.record", "CVE-2026-55555")
    job = await env.repository.claim(uuid4(), 30)
    assert job is not None and job.id == job_id
    context = ExecutionContext(
        env.repository, job, env.service.registry().get(job.job_type, 1), asyncio.Event()
    )
    with env.lab.owner() as c:
        c.execute(
            "UPDATE automation.jobs SET "
            "lease_until=clock_timestamp()-interval '1 second' WHERE id=%s",
            (job.id,),
        )
    with pytest.raises(LeaseLost):
        await env.service.handle(context, Request(identity="CVE-2026-55555"))
    with env.lab.owner() as c:
        assert (
            c.execute(
                "SELECT 1 FROM cve.enrichment_identities WHERE identity='CVE-2026-55555'"
            ).fetchone()
            is None
        )
    await env.repository.recover()
    with env.lab.owner() as c:
        c.execute(
            "UPDATE automation.jobs SET scheduled_at=clock_timestamp() WHERE id=%s", (job.id,)
        )
    await env.drain()
    assert env.row("CVE-2026-55555")["result"]["lifecycle"]["value"] == "unknown"


async def test_backup_restore_includes_enrichment_and_epss(env: Env, tmp_path: Path) -> None:
    target = tmp_path / "backup"
    db.backup(env.lab.config, target)
    assert db.restore_test(env.lab.config, target)


async def test_reverted_inputs_emit_new_transition_without_duplicate_revision(env: Env) -> None:
    from tests.cve_importer.fixtures import cve

    env.importer.wire.cve = [cve()]
    await env.importer.run("cve_list", "reconcile")
    await env.drain()
    original = env.row()
    with env.lab.owner() as c:
        events = required_row(
            c.execute(
                "SELECT count(*) AS n FROM automation.event_outbox WHERE "
                "event_type IN "
                "('cve.enrichment.created','cve.enrichment.changed') AND "
                "payload->>'identity'='CVE-2026-12345'"
            )
        )["n"]
    env.importer.wire.cve = [cve(state="REJECTED")]
    await env.importer.run("cve_list", "reconcile")
    await env.drain()
    env.importer.wire.cve = [cve()]
    await env.importer.run("cve_list", "reconcile")
    await env.drain()
    result = env.row()
    assert result["id"] == original["id"]
    assert result["current_version"] == original["current_version"] + 2
    with env.lab.owner() as c:
        assert (
            required_row(
                c.execute(
                    "SELECT count(*) AS n FROM automation.event_outbox WHERE "
                    "event_type IN "
                    "('cve.enrichment.created','cve.enrichment.changed') AND "
                    "payload->>'identity'='CVE-2026-12345'"
                )
            )["n"]
            == events + 2
        )


async def test_epss_republication_emits_a_fresh_transition(env: Env) -> None:
    manage.enqueue(env.lab.config, "cve.epss.sync_daily")
    await env.drain()
    with env.lab.owner() as c:
        original = required_row(c.execute("SELECT * FROM cve.epss_current_dataset"))
        before = required_row(
            c.execute(
                "SELECT count(*) AS n FROM automation.event_outbox WHERE "
                "event_type='cve.enrichment.epss_updated'"
            )
        )["n"]
    raw = env.csv
    env.csv = raw.replace(b"0.123456789", b"0.333456789")
    manage.enqueue(env.lab.config, "cve.epss.sync_daily")
    await env.drain()
    env.csv = raw
    manage.enqueue(env.lab.config, "cve.epss.sync_daily")
    await env.drain()
    with env.lab.owner() as c:
        current = required_row(c.execute("SELECT * FROM cve.epss_current_dataset"))
        assert current["dataset_id"] == original["dataset_id"]
        assert current["current_version"] == original["current_version"] + 2
        assert (
            required_row(
                c.execute(
                    "SELECT count(*) AS n FROM automation.event_outbox WHERE "
                    "event_type='cve.enrichment.epss_updated'"
                )
            )["n"]
            == before + 2
        )


async def test_long_advisory_identity_uses_bounded_job_and_event_keys(env: Env) -> None:
    from tests.cve_importer.fixtures import osv

    identity = "OSV-" + "a" * 240
    value = osv(identity)
    value["aliases"] = []
    env.importer.wire.osv = [value]
    await env.importer.run("osv", "reconcile")
    await env.drain()
    assert env.row(identity)["kind"] == "advisory"
    with env.lab.owner() as c:
        assert c.execute(
            "SELECT 1 FROM automation.event_outbox WHERE payload->>'identity'=%s", (identity,)
        ).fetchone()


async def test_performance_batched_backfill_and_epss(env: Env) -> None:
    import time

    # Existing indexed source identifiers are enough to demonstrate bounded continuation.
    with env.lab.owner() as c:
        c.execute(
            "INSERT INTO cve.source_identifiers(identifier,kind) SELECT "
            "'CVE-2026-'||(60000+v)::text,'cve' FROM generate_series(1,1000) "
            "v ON CONFLICT DO NOTHING"
        )
    env.cfg = env.cfg.model_copy(update={"batch_size": 250})
    env.service.cfg = env.cfg
    env.client.cfg = env.cfg
    start = time.monotonic()
    manage.enqueue(env.lab.config, "cve.enrich.backfill")
    for _ in range(1200):
        if await env.execute() is None:
            break
    else:
        raise AssertionError("Backfill failed to terminate")
    with env.lab.owner() as c:
        assert (
            required_row(
                c.execute(
                    "SELECT count(*) AS n FROM cve.enrichment_identities WHERE "
                    "identity>'CVE-2026-60000' AND identity<'CVE-2026-61001'"
                )
            )["n"]
            == 1000
        )
    assert time.monotonic() - start < 120


async def test_performance_epss_bulk_is_not_enrichment_fanout(env: Env) -> None:
    import time

    env.cfg = env.cfg.model_copy(update={"batch_size": 1000})
    env.service.cfg = env.cfg
    env.client.cfg = env.cfg
    header = env.csv.split(b"\n", 2)[:2]
    env.csv = (
        b"\n".join(header)
        + b"\n"
        + b"".join(f"CVE-2026-{70000 + i},0.123456789,0.987654321\n".encode() for i in range(10000))
    )
    with env.lab.owner() as c:
        before = required_row(c.execute("SELECT count(*) AS n FROM cve.enrichment_revisions"))["n"]
    started = time.monotonic()
    manage.enqueue(env.lab.config, "cve.epss.sync_daily")
    await env.drain()
    with env.lab.owner() as c:
        assert (
            required_row(c.execute("SELECT count(*) AS n FROM cve.current_epss_scores"))["n"]
            == 10000
        )
        assert (
            required_row(c.execute("SELECT count(*) AS n FROM cve.enrichment_revisions"))["n"]
            == before
        )
    assert time.monotonic() - started < 60


async def test_complete_operations_metrics_without_privilege_expansion(env: Env) -> None:
    with db.connect(env.lab.config, "enricher") as c:
        metrics = required_row(c.execute("SELECT cve.enricher_metrics() AS data"))["data"]
        assert {
            "queued",
            "successful_enrichments",
            "failed_enrichments",
            "conflicts",
            "valid_cvss_fraction",
            "cvss_versions",
            "kev_age_hours",
            "current_epss",
            "epss_import_duration_ms",
            "enrichment_duration_ms",
            "retry_count",
            "backfill_progress",
            "active_workers",
            "outbox_backlog",
        } <= set(metrics)
        assert metrics["outbox_backlog"] == 0
        assert metrics["enrichment_duration_ms"] is not None


async def test_record_reconcile_avoids_a_second_job_per_identity(env: Env) -> None:
    await env.drain()
    with env.lab.owner() as conn:
        before = conn.execute(
            "SELECT count(*) n FROM automation.jobs WHERE job_type='cve.enrich.record'"
        ).fetchone()
    value = env.importer.wire.cve[0]
    value["containers"]["cna"]["descriptions"][0]["value"] += " Direct reconcile regression."
    await env.importer.run("cve_list", "reconcile")
    await env.drain()
    with env.lab.owner() as conn:
        after = conn.execute(
            "SELECT count(*) n FROM automation.jobs WHERE job_type='cve.enrich.record'"
        ).fetchone()
    assert before == after


async def test_daily_feed_is_not_starved_by_record_backlog(env: Env, tmp_path: Path) -> None:
    import os

    from cve_enricher.contracts import Settings
    from cve_enricher.main import Repository

    for _ in range(8):
        manage.enqueue(env.lab.config, "cve.enrich.record", "CVE-2026-12345")
    manage.enqueue(env.lab.config, "cve.epss.sync_daily")
    proof = tmp_path / "egress.proof"
    proof.write_text(os.readlink("/proc/self/ns/net"))
    proof.chmod(0o600)
    settings = Settings(
        app_env="test",
        database=env.lab.settings("enricher"),
        configuration_file=tmp_path / "configuration.json",
        egress_proof_file=proof,
    )
    repository = Repository(env.service, settings)
    job = await repository.claim(uuid4(), 30)
    assert job is not None and job.job_type == "cve.epss.sync_daily"
    # This test covers scheduling; publication and regression checks have separate tests.
    from cve_common.jobs.errors import ErrorCode

    assert await repository.finish(job, "failed", ErrorCode.PERMANENT)
    await env.drain()


async def prepared_jobs(env: Env, identities: list[str]) -> list[Any]:
    from cve_enricher.bulk import prepare

    for identity in identities:
        manage.enqueue(env.lab.config, "cve.enrich.record", identity)
    from cve_common.jobs.registry import Registry

    registry = Registry()
    registry.register(env.service.registry().get("cve.enrich.record", 1))
    records = JobRepository(env.database, registry)
    entries = []
    for identity in identities:
        job = await records.claim(uuid4(), 30)
        assert job is not None and job.payload["identity"] == identity
        context = ExecutionContext(
            env.repository, job, env.service.registry().get(job.job_type, 1), asyncio.Event()
        )
        value = await prepare(env.database, identity, job.id, job.correlation_id, env.cfg)
        entries.append((context, value))
    return entries


async def test_bulk_writer_constant_roundtrips_and_atomic_acknowledgement(env: Env) -> None:
    from sqlalchemy import event

    from tests.cve_importer.fixtures import cve

    identities = [f"CVE-2098-{10000 + i}" for i in range(8)]
    env.importer.wire.cve = [cve(identifier=identity) for identity in identities]
    await env.importer.run("cve_list", "reconcile")
    entries = await prepared_jobs(env, identities)
    assert all(value.refs and value.document["descriptions"] for _, value in entries)
    assert env.database.engine is not None
    statements = []

    def record(*args: Any) -> None:
        statements.append(args[2])

    event.listen(env.database.engine.sync_engine, "before_cursor_execute", record)
    before = env.pipeline.batches
    try:
        results = await asyncio.gather(*(env.pipeline.submit(c, [v]) for c, v in entries))
    finally:
        event.remove(env.database.engine.sync_engine, "before_cursor_execute", record)
    assert all(r.changed for r in results)
    assert env.pipeline.batches == before + 1
    # Includes all input locks/revalidation, revision writes, outbox and eight fenced completions.
    assert len(statements) <= 15
    with env.lab.owner() as c:
        assert (
            required_row(
                c.execute(
                    "SELECT count(*) AS n FROM automation.jobs "
                    "WHERE id=ANY(%s) AND status='succeeded'",
                    ([context.job.id for context, _ in entries],),
                )
            )["n"]
            == 8
        )
        assert (
            required_row(
                c.execute(
                    "SELECT count(*) AS n FROM cve.enrichment_identities "
                    "WHERE identity=ANY(%s) AND current_version=1",
                    ([v.identity for _, v in entries],),
                )
            )["n"]
            == 8
        )
    assert all(context.completed for context, _ in entries)
    await env.drain()
    duplicates = await prepared_jobs(env, identities)
    statements.clear()
    event.listen(env.database.engine.sync_engine, "before_cursor_execute", record)
    try:
        repeated = await asyncio.gather(*(env.pipeline.submit(c, [v]) for c, v in duplicates))
    finally:
        event.remove(env.database.engine.sync_engine, "before_cursor_execute", record)
    assert not any(result.changed for result in repeated)
    assert len(statements) <= 8


async def test_stale_preparation_is_retried_without_stale_publication(env: Env) -> None:
    from cve_common.jobs.errors import ErrorCode, JobError

    [(context, value)] = await prepared_jobs(env, ["CVE-2026-12345"])
    before = env.row()["id"]
    record = value.refs[0]
    with env.lab.owner() as c:
        c.execute("UPDATE cve.source_records SET present=NOT present WHERE id=%s", (record["id"],))
    try:
        with pytest.raises(JobError) as error:
            await env.pipeline.submit(context, [value])
        assert error.value.code == ErrorCode.TEMPORARY
        assert not context.completed and env.row()["id"] == before
    finally:
        with env.lab.owner() as c:
            c.execute(
                "UPDATE cve.source_records SET present=%s WHERE id=%s",
                (record["present"], record["id"]),
            )
        await env.repository.finish(context.job, "retry", ErrorCode.TEMPORARY)
        with env.lab.owner() as c:
            c.execute(
                "UPDATE automation.jobs SET scheduled_at=clock_timestamp() WHERE id=%s",
                (context.job.id,),
            )
    await env.drain()


async def test_invalid_lease_does_not_block_healthy_batch_neighbours(env: Env) -> None:
    from cve_common.jobs.errors import LeaseLost

    entries = await prepared_jobs(env, ["CVE-2098-20001", "CVE-2098-20002"])
    with env.lab.owner() as c:
        c.execute(
            "UPDATE automation.jobs SET lease_until=clock_timestamp()-interval '1 second' "
            "WHERE id=%s",
            (entries[0][0].job.id,),
        )
    results = await asyncio.gather(
        *(env.pipeline.submit(c, [v]) for c, v in entries), return_exceptions=True
    )
    assert isinstance(results[0], LeaseLost)
    assert not entries[0][0].completed
    assert entries[1][0].completed
    assert isinstance(results[1], Result) and results[1].changed
    with env.lab.owner() as c:
        assert (
            c.execute(
                "SELECT 1 FROM cve.enrichment_identities WHERE identity='CVE-2098-20001'"
            ).fetchone()
            is None
        )
    await env.repository.recover()
    with env.lab.owner() as c:
        c.execute(
            "UPDATE automation.jobs SET scheduled_at=clock_timestamp() WHERE id=%s",
            (entries[0][0].job.id,),
        )
    await env.drain()


async def test_writer_shutdown_rolls_back_and_original_job_recovers(env: Env) -> None:
    from cve_common.jobs.errors import JobError

    [(context, value)] = await prepared_jobs(env, ["CVE-2098-30001"])
    # Stop the writer inside a real transaction, before it can publish any results.
    lock = env.lab.owner()
    lock.execute("SELECT pg_advisory_lock(hashtextextended(%s,16))", (value.identity,))
    pending = asyncio.create_task(env.pipeline.submit(context, [value]))
    try:
        async with asyncio.timeout(5):
            while not env.pipeline.writing:
                await asyncio.sleep(0.01)
        await env.pipeline.close()
        with pytest.raises(JobError):
            await pending
        assert not context.completed
        assert (
            lock.execute(
                "SELECT 1 FROM cve.enrichment_identities WHERE identity=%s", (value.identity,)
            ).fetchone()
            is None
        )
    finally:
        lock.execute("SELECT pg_advisory_unlock(hashtextextended(%s,16))", (value.identity,))
        lock.close()
    with env.lab.owner() as c:
        c.execute(
            "UPDATE automation.jobs SET lease_until=clock_timestamp()-interval '1 second' "
            "WHERE id=%s",
            (context.job.id,),
        )
    await env.repository.recover()
    with env.lab.owner() as c:
        c.execute(
            "UPDATE automation.jobs SET scheduled_at=clock_timestamp() WHERE id=%s",
            (context.job.id,),
        )
    env.pipeline = Pipeline(env.database)
    env.pipeline.start()
    env.service.pipeline = env.pipeline
    await env.drain()
    assert env.row(value.identity)["current_version"] == 1


async def test_real_source_bulk_write_comparison(env: Env) -> None:
    """Compare equal, new nonempty CVEs against the previous per-record repository path."""
    import json
    import time

    from cve_common.database.transactions import transaction
    from cve_enricher.bulk import prepare_many, publish
    from cve_enricher.repository import enrich
    from sqlalchemy import event

    from tests.cve_importer.fixtures import cve

    identities = [f"CVE-2097-{10000 + i}" for i in range(64)]
    env.importer.wire.cve = [cve(identifier=identity) for identity in identities]
    await env.importer.run("cve_list", "reconcile")
    job = manage.enqueue(env.lab.config, "cve.enrich.record", identities[0])
    correlation = uuid4()
    assert env.database.engine is not None
    statements: list[str] = []

    def record(*args: Any) -> None:
        statements.append(args[2])

    event.listen(env.database.engine.sync_engine, "before_cursor_execute", record)
    try:
        started = time.monotonic()
        for identity in identities[:32]:
            async with transaction(env.database) as session:
                result = await enrich(session, identity, job, correlation, env.cfg)
                assert result.changed
        old_seconds, old_calls = time.monotonic() - started, len(statements)
        statements.clear()
        started = time.monotonic()
        prepared = await prepare_many(env.database, identities[32:], job, correlation, env.cfg)
        preparation_calls = len(statements)
        assert preparation_calls <= 5
        async with transaction(env.database) as session:
            results = await publish(session, prepared)
        new_seconds, new_calls = time.monotonic() - started, len(statements)
        assert all(r.changed for r in results)
        assert all(v.refs and v.document["descriptions"] for v in prepared)
        assert new_calls - preparation_calls <= 15
        assert new_calls < old_calls * 0.7
    finally:
        event.remove(env.database.engine.sync_engine, "before_cursor_execute", record)
    report = {
        "records_per_variant": 32,
        "nonempty_source": "cve_list",
        "previous": {"seconds": old_seconds, "sql_calls": old_calls},
        "pipeline": {
            "seconds": new_seconds,
            "sql_calls": new_calls,
            "write_calls": new_calls - preparation_calls,
        },
        "speedup": old_seconds / new_seconds,
    }
    destination = env.lab.config.root / ".runtime/test-reports/enrichment-batch-synthetic.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    await env.drain()


async def test_package_preparation_matches_individual_source_policy(env: Env) -> None:
    from cve_enricher.bulk import prepare, prepare_many
    from sqlalchemy import event

    identities = ["CVE-2026-12345", "CVE-2026-12346", "GHSA-abcd-1234-5678"]
    job = uuid4()
    correlation = uuid4()
    individual = [
        await prepare(env.database, identity, job, correlation, env.cfg)
        for identity in sorted(identities)
    ]
    assert env.database.engine is not None
    statements: list[str] = []

    def record(*args: Any) -> None:
        statements.append(args[2])

    event.listen(env.database.engine.sync_engine, "before_cursor_execute", record)
    try:
        package = await prepare_many(env.database, identities, job, correlation, env.cfg)
    finally:
        event.remove(env.database.engine.sync_engine, "before_cursor_execute", record)
    assert package == individual
    assert len(statements) <= 5


async def test_batch_job_publishes_package_and_acknowledges_once(env: Env) -> None:
    import json

    from cve_common.jobs.registry import Registry

    identities = ["CVE-2026-12345", "CVE-2026-12346", "CVE-2096-10001"]
    with db.connect(env.lab.config, "api_security") as connection:
        job_id = required_row(
            connection.execute(
                """
SELECT id FROM automation.enqueue_job('cve.enrich.batch',1,%s::jsonb,%s,%s,
0,NULL,NULL,3,'synthetic-git-batch',false)
""",
                (json.dumps({"identities": identities}), str(uuid4()), uuid4()),
            )
        )["id"]
    registry = Registry()
    registry.register(env.service.registry().get("cve.enrich.batch", 1))
    repository = JobRepository(env.database, registry)
    job = await repository.claim(uuid4(), 30)
    assert job is not None and job.id == job_id
    context = ExecutionContext(repository, job, registry.get(job.job_type, 1), asyncio.Event())
    result = await env.service.handle(context, Request(identities=identities))
    assert context.completed and result.count == 3
    assert env.row("CVE-2096-10001")["current_version"] == 1
    with env.lab.owner() as connection:
        assert (
            required_row(
                connection.execute("SELECT status FROM automation.jobs WHERE id=%s", (job_id,))
            )["status"]
            == "succeeded"
        )


async def test_granular_events_schedule_one_match_and_no_empty_priority_refresh(env: Env) -> None:
    identity = "CVE-2095-10001"
    manage.enqueue(env.lab.config, "cve.enrich.record", identity)
    await env.drain()
    with env.lab.owner() as connection:
        jobs = required_row(
            connection.execute(
                "SELECT count(*) n FROM automation.jobs "
                "WHERE job_type='matching.evaluate_vulnerability' AND payload->>'identity'=%s",
                (identity,),
            )
        )["n"]
        priorities = required_row(
            connection.execute(
                "SELECT count(*) n FROM automation.jobs "
                "WHERE job_type='findings.refresh_priority' AND payload->>'identity'=%s",
                (identity,),
            )
        )["n"]
        events = required_row(
            connection.execute(
                "SELECT count(*) n FROM automation.event_outbox "
                "WHERE source='cve-enricher' AND payload->>'identity'=%s",
                (identity,),
            )
        )["n"]
    assert events > 1 and jobs == 1 and priorities == 0


async def test_independent_writers_do_not_block_unrelated_identities(env: Env) -> None:
    entries = await prepared_jobs(env, ["CVE-2094-10001", "CVE-2094-10002"])
    second = Pipeline(env.database)
    second.start()
    lock = env.lab.owner()
    lock.execute("SELECT pg_advisory_lock(hashtextextended(%s,16))", (entries[0][1].identity,))
    blocked = asyncio.create_task(env.pipeline.submit(entries[0][0], [entries[0][1]]))
    try:
        async with asyncio.timeout(3):
            while not env.pipeline.writing:
                await asyncio.sleep(0.01)
        result = await asyncio.wait_for(second.submit(entries[1][0], [entries[1][1]]), 3)
        assert result.changed and entries[1][0].completed and not blocked.done()
    finally:
        lock.execute(
            "SELECT pg_advisory_unlock(hashtextextended(%s,16))", (entries[0][1].identity,)
        )
        lock.close()
        await blocked
        await second.close()


async def test_two_writers_publish_same_identity_once(env: Env) -> None:
    identity = "CVE-2094-20001"
    entries = await prepared_jobs(env, [identity, identity])
    second = Pipeline(env.database)
    second.start()
    try:
        results = await asyncio.gather(
            env.pipeline.submit(entries[0][0], [entries[0][1]]),
            second.submit(entries[1][0], [entries[1][1]]),
        )
    finally:
        await second.close()
    assert sum(result.changed for result in results) == 1
    assert env.row(identity)["current_version"] == 1
    assert all(context.completed for context, _ in entries)
