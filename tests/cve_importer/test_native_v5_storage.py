"""Compare the previous batched postprocessing with native publication on equal source data."""

import asyncio
import importlib
import json
import time
from dataclasses import replace
from uuid import uuid4

import pytest
from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_common.jobs.execution import ExecutionContext
from cve_enricher.bulk import prepare_many, publish
from cve_enricher.contracts import Configuration
from cve_importer.contracts import Result as ImportResult
from cve_importer.repository import publish_native
from sqlalchemy import event, text

from tests.cve_importer.fixtures import cve
from tests.cve_importer.test_pipeline import Harness, harness

__all__ = ["harness"]
pytestmark = pytest.mark.cve_importer


async def test_existing_v5_revisions_convert_without_changing_evidence_ids(
    harness: Harness,
) -> None:
    from cve_common.v5 import revisions
    from cve_matcher.service import index_revision

    identities = ["CVE-2096-98001", "CVE-2096-98002", "CVE-2096-98003"]
    harness.wire.cve = [cve(identifier=i) for i in identities]
    run = await harness.run("cve_list")
    enrichment = Database(harness.lab.settings("enricher"))
    enrichment.open()
    matcher = Database(harness.lab.settings("matcher"))
    matcher.open()
    try:
        prepared = await prepare_many(
            enrichment, identities, run["job_id"], uuid4(), Configuration()
        )
        # Simulate the historical V5-only input rather than importing a previous case's KEV catalog.
        unknown_kev = {"status": "unknown", "reason": "catalog_unavailable", "provenance": None}
        prepared = [
            replace(v, document={**v.document, "kev": unknown_kev}, kev=unknown_kev)
            for v in prepared[:2]
        ] + [
            replace(
                prepared[2],
                document={**prepared[2].document, "kev": {"status": "absent"}},
                kev={"status": "absent"},
            )
        ]
        async with transaction(enrichment) as s:
            results = await publish(s, prepared)
        ids = [r.revision_id for r in results]
        assert all(ids)
        originals = {}
        async with transaction(matcher) as s:
            for revision in ids:
                assert revision is not None
                originals[revision] = (await index_revision(s, revision))["result"]
        migration = importlib.import_module("database.migrations.versions.00039_native_v5_json")
        with harness.lab.owner() as c:
            c.execute(migration.BACKFILL, prepare=False)
            handles = c.execute(
                "SELECT identity,current_revision_id FROM cve.enrichment_identities "
                "WHERE identity=ANY(%s) ORDER BY identity",
                (identities,),
            ).fetchall()
            assert [r["current_revision_id"] for r in handles] == ids
            assert not c.execute(
                "SELECT 1 FROM cve.enrichment_assertions WHERE enrichment_revision_id=ANY(%s)",
                (ids[:2],),
            ).fetchone()
            assert c.execute(
                "SELECT 1 FROM cve.enrichment_assertions WHERE enrichment_revision_id=%s",
                (ids[2],),
            ).fetchone()
            indexed = c.execute(
                "SELECT count(*) n FROM matching.indexed_revisions "
                "WHERE enrichment_revision_id=ANY(%s)",
                (ids,),
            ).fetchone()
            assert indexed is not None and indexed["n"] == 3
        async with transaction(matcher) as s:
            converted = await revisions(s, [r for r in ids if r is not None], include_cvss=True)
        for row in converted:
            for field in ("affected", "lifecycle", "cvss"):
                assert row["result"][field] == originals[row["id"]][field]
    finally:
        await enrichment.close()
        await matcher.close()


async def test_native_publication_avoids_normalized_copies(harness: Harness) -> None:
    identities = [f"CVE-2096-{90000 + i}" for i in range(64)]
    harness.wire.cve = [cve(identifier=i) for i in identities]
    await harness.run("cve_list")
    harness.configuration = harness.configuration.model_copy(
        update={
            "enabled": ["cve_list"],
            "cve_list_transport": "git",
            "enrichment_batch_size": 64,
        }
    )
    run_id = harness.schedule("cve_list", "incremental")
    job = await harness.repository.claim(uuid4(), 300)
    assert job is not None and job.payload["run_id"] == str(run_id)
    context = ExecutionContext(
        harness.repository, job, harness.repository.registry.get(job.job_type, 1), asyncio.Event()
    )
    async with context.atomic() as session:
        await session.execute(
            text("UPDATE cve.import_runs SET status='running',job_id=:job WHERE id=:id"),
            {"id": run_id, "job": job.id},
        )
        await session.execute(
            text("UPDATE cve.source_records SET last_seen_run=:run WHERE external_id=ANY(:ids)"),
            {"run": run_id, "ids": identities[32:]},
        )
    previous = Database(harness.lab.settings("enricher"))
    previous.open()
    assert previous.engine is not None and harness.database.engine is not None
    statements: dict[str, int] = {"previous": 0, "native": 0}

    def old_call(*args: object) -> None:
        statements["previous"] += 1

    def new_call(*args: object) -> None:
        statements["native"] += 1

    event.listen(previous.engine.sync_engine, "before_cursor_execute", old_call)
    event.listen(harness.database.engine.sync_engine, "before_cursor_execute", new_call)
    try:
        started = time.monotonic()
        prepared = await prepare_many(
            previous, identities[:32], job.id, job.correlation_id, Configuration()
        )
        async with transaction(previous) as session:
            results = await publish(session, prepared)
        previous_seconds = time.monotonic() - started
        assert all(r.changed for r in results)
        started = time.monotonic()
        async with context.atomic() as session:
            await publish_native(
                session,
                {"id": run_id, "correlation_id": job.correlation_id},
                identities[32:],
                harness.configuration,
            )
        native_seconds = time.monotonic() - started
        with harness.lab.owner() as connection:
            sizes = {}
            for name, group in (("previous", identities[:32]), ("native", identities[32:])):
                sizes[name] = connection.execute(
                    """
SELECT sum(octet_length(result::text)) AS result_bytes,
 (SELECT count(*) FROM cve.enrichment_assertions a JOIN cve.enrichment_revisions e
 ON e.id=a.enrichment_revision_id WHERE e.identity=ANY(%s)) AS assertion_rows
FROM cve.enrichment_revisions WHERE identity=ANY(%s)
""",
                    (group, group),
                ).fetchone()
            assert sizes["native"] is not None and sizes["previous"] is not None
            assert sizes["native"]["assertion_rows"] == 0
            assert sizes["previous"]["assertion_rows"] > 0
            assert sizes["native"]["result_bytes"] < sizes["previous"]["result_bytes"] / 10
        assert statements["native"] < statements["previous"]
        report = {
            "records_per_variant": 32,
            "scope": "postprocessing/publication; raw import excluded",
            "previous": {
                "seconds": previous_seconds,
                "sql_calls": statements["previous"],
                **sizes["previous"],
            },
            "native": {
                "seconds": native_seconds,
                "sql_calls": statements["native"],
                **sizes["native"],
            },
            "speedup": previous_seconds / native_seconds,
        }
        destination = (
            harness.lab.config.root / ".runtime/test-reports/native-v5-storage-benchmark.json"
        )
        destination.write_text(json.dumps(report, indent=2) + "\n")

        async def complete(session: object) -> ImportResult:
            from sqlalchemy.ext.asyncio import AsyncSession

            assert isinstance(session, AsyncSession)
            await session.execute(
                text(
                    "UPDATE cve.import_runs SET status='completed',finished_at=clock_timestamp() "
                    "WHERE id=:id"
                ),
                {"id": run_id},
            )
            await session.execute(
                text("UPDATE cve.source_leases SET active_run=NULL WHERE active_run=:id"),
                {"id": run_id},
            )
            return ImportResult(run_id=run_id, status="completed")

        await context.complete(complete)
    finally:
        event.remove(previous.engine.sync_engine, "before_cursor_execute", old_call)
        event.remove(harness.database.engine.sync_engine, "before_cursor_execute", new_call)
        await previous.close()
