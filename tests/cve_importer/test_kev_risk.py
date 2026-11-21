"""A complete KEV catalog enriches native V5 risk without rewriting its document."""

import importlib
from uuid import uuid4

import pytest
from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_enricher.bulk import prepare_many, publish
from cve_enricher.contracts import Configuration
from cve_findings.repository import signals

from tests.cve_importer.test_pipeline import Harness, harness

__all__ = ["harness"]
pytestmark = pytest.mark.cve_importer


async def test_complete_kev_catalog_updates_native_risk_without_rewriting_v5(
    harness: Harness,
) -> None:
    identity = "CVE-2026-12345"
    run = await harness.run("cve_list")
    enrichment = Database(harness.lab.settings("enricher"))
    enrichment.open()
    findings = Database(harness.lab.settings("findings_writer"))
    findings.open()
    try:
        values = await prepare_many(enrichment, [identity], run["job_id"], uuid4(), Configuration())
        async with transaction(enrichment) as session:
            before = (await publish(session, values))[0].revision_id
        conversion = importlib.import_module("database.migrations.versions.00039_native_v5_json")
        with harness.lab.owner() as session:
            session.execute(conversion.BACKFILL, prepare=False)
            original = session.execute(
                "SELECT document_revision_id FROM cve.enrichment_revisions WHERE id=%s", (before,)
            ).fetchone()
            assert original and original["document_revision_id"]
        async with transaction(findings) as session:
            baseline = await signals(session, identity)
            assert baseline.kev_status == "unknown"
        # A real V5 Git import leaves a nested persistent working tree beside
        # download directories. KEV must coexist without treating it as a file.
        git_cache = harness.transport.scratch / "git"
        git_cache.mkdir(mode=0o700)
        (git_cache / "cvelistV5" / ".git").mkdir(parents=True)
        await harness.run("cisa_kev")
        async with transaction(findings) as session:
            risk = await signals(session, identity)
            assert risk.kev_status == "present" and risk.kev_is_current
            assert risk.kev_due_date
            assert risk.cvss == baseline.cvss
        with harness.lab.owner() as session:
            after = session.execute(
                "SELECT id,document_revision_id,result FROM cve.enrichment_revisions WHERE id=%s",
                (before,),
            ).fetchone()
            assert after and after["document_revision_id"] == original["document_revision_id"]
            assert after["result"] == {"storage": "v5-json"}
            absent = session.execute("SELECT cve.kev_risk('CVE-2099-99999') value").fetchone()
            assert absent and absent["value"]["status"] == "absent"
            assert session.execute(
                "SELECT 1 FROM automation.jobs WHERE job_type='findings.refresh_priority' LIMIT 1"
            ).fetchone()
            session.execute(
                "UPDATE cve.source_streams SET "
                "last_success_at=clock_timestamp()-interval '80 hours' "
                "WHERE source_id='cisa_kev'"
            )
        async with transaction(findings) as session:
            stale = await signals(session, identity)
            assert stale.kev_status == "unknown" and not stale.kev_is_current
    finally:
        await enrichment.close()
        await findings.close()
