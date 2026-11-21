"""Native V5 documents retain their revision while fresh EPSS updates finding risk."""

import importlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_findings.repository import signals

from scripts.cve_enricher import manage
from tests.cve_enricher.test_native import Env
from tests.cve_importer.conftest import Lab
from tests.orchestration.test_epss_control import epss_lab

__all__ = ["epss_lab"]
pytestmark = pytest.mark.cve_enricher


async def test_epss_updates_native_finding_signals_without_rewriting_v5(
    epss_lab: Lab, tmp_path: Path
) -> None:
    env = Env(epss_lab, tmp_path)
    findings = Database(epss_lab.settings("findings_writer"))
    findings.open()
    try:
        await env.importer.run("cve_list")
        await env.drain()
        conversion = importlib.import_module("database.migrations.versions.00039_native_v5_json")
        with epss_lab.owner() as s:
            s.execute(conversion.BACKFILL, prepare=False)
            before = s.execute(
                "SELECT id,document_revision_id,result FROM cve.enrichment_revisions "
                "WHERE document_revision_id IS NOT NULL ORDER BY id"
            ).fetchall()
            assert before
        async with transaction(findings) as s:
            baseline = await signals(s, "CVE-2026-12345")
            assert baseline.epss is None
        env.csv = env.csv.replace(b"2026-11-07", datetime.now(UTC).date().isoformat().encode())
        manage.enqueue(epss_lab.config, "cve.epss.sync_daily")
        await env.drain()
        async with transaction(findings) as s:
            current = await signals(s, "CVE-2026-12345")
            assert current.epss and float(current.epss["score"]) == 0.123456789
            assert float(current.epss["percentile"]) == 0.987654321
            assert current.epss["is_stale"] is False
            assert current.cvss == baseline.cvss and current.kev_status == baseline.kev_status
        with epss_lab.owner() as s:
            assert (
                before
                == s.execute(
                    "SELECT id,document_revision_id,result FROM cve.enrichment_revisions "
                    "WHERE document_revision_id IS NOT NULL ORDER BY id"
                ).fetchall()
            )
            assert s.execute(
                "SELECT 1 FROM automation.jobs WHERE job_type='findings.refresh_priority'"
            ).fetchone()
    finally:
        await findings.close()
        await env.importer.transport.close()
        await env.importer.database.close()
        await env.pipeline.close()
        await env.client.close()
        await env.database.close()
