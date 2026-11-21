"""Native Git JSON acceptance through real inventory, matching, priority and findings."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.authentication.integration.conftest import Lab as UploadLab
from tests.cve_importer.conftest import Lab
from tests.cve_importer.test_git_source import upstream as upstream
from tests.inventory_upload.integration.conftest import isolated_upload_lab
from tests.matching.test_native import Harness
from tests.matching.test_native import harness as harness

pytestmark = pytest.mark.matching


@pytest.fixture(scope="module")
def upload_lab() -> Iterator[UploadLab]:
    # V5-only full scans intentionally withdraw records absent from Git. They must not
    # share a source catalog with the historical multi-source regression scenarios.
    yield from isolated_upload_lab()


async def test_native_git_json_to_matching_findings_and_rejection(
    harness: "Harness", tmp_path: Path, upstream: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.cve_importer.test_git_source import configure, write
    from tests.cve_importer.test_pipeline import Harness as Importer
    from tests.findings.test_native import Harness as Findings

    root, commit = upstream
    identity = "CVE-2096-97001"
    path = write(root, identity)
    raw = json.loads(path.read_text())
    raw["containers"]["cna"]["affected"] = [
        {
            "vendor": "Apache",
            "product": "apache2",
            "defaultStatus": "unknown",
            "versions": [
                {"version": "0", "lessThan": "99", "versionType": "debian", "status": "affected"}
            ],
        }
    ]
    raw["containers"]["cna"]["metrics"] = [
        {
            "cvssV3_1": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL",
            }
        }
    ]
    path.write_text(json.dumps(raw))
    # A prefix pair catches keyset ordering bugs: appending ':' changes lexical order.
    other = identity + "0"
    other_path = write(root, other)
    second = json.loads(json.dumps(raw))
    second["cveMetadata"]["cveId"] = other
    other_path.write_text(json.dumps(second))
    commit()
    importer = Importer(Lab(harness.browser.lab.config), tmp_path / "git-import")
    configure(importer)
    findings = Findings(harness.browser)
    try:
        snapshot = await harness.snapshot()
        import cve_matcher.service as matcher_service

        monkeypatch.setattr(matcher_service, "PAGE", 1)
        await importer.run("cve_list")
        assert (
            await harness.browser.login(
                "upload-initial-admin", harness.browser.lab.bootstrap_password
            )
        ).status_code == 200
        endpoint = "/api/v1/dashboard/cve-data/documents"
        response = await harness.browser.client.get(endpoint + "/" + identity)
        assert response.status_code == 200 and response.json()["document"] == raw
        listing = await harness.browser.client.get(endpoint)
        assert listing.status_code == 200
        assert any(r["identity"] == identity for r in listing.json()["items"])
        assert "document" not in listing.json()["items"][0]
        await harness.drain()
        await findings.drain()
        with harness.browser.lab.owner() as c:
            finding = c.execute(
                "SELECT * FROM findings.current_findings WHERE cve_id=%s AND "
                "latest_matching_result_id IN (SELECT id FROM matching.result_revisions "
                "WHERE snapshot_id=%s)",
                (identity, snapshot),
            ).fetchone()
            assert finding and finding["status"] == "open"
            assert c.execute(
                "SELECT 1 FROM findings.current_findings WHERE cve_id=%s AND status='open'",
                (other,),
            ).fetchone(), "Every candidate must survive keyset pagination"
            assert finding["latest_matching_status"] in {"affected", "potentially_affected"}
            signal = c.execute(
                "SELECT signals FROM findings.priority_history WHERE finding_id=%s "
                "ORDER BY created_at DESC LIMIT 1",
                (finding["id"],),
            ).fetchone()
            assert signal["signals"]["cvss"]["base_score"] == 9.8
            assert c.execute(
                "SELECT 1 FROM matching.result_evidence WHERE result_id=%s",
                (finding["latest_matching_result_id"],),
            ).fetchone()
        path.unlink()
        commit()
        await importer.run("cve_list", "incremental")
        await harness.drain()
        await findings.drain()
        with harness.browser.lab.owner() as c:
            removed = c.execute(
                "SELECT * FROM findings.current_findings WHERE id=%s", (finding["id"],)
            ).fetchone()
            assert removed["latest_matching_status"] == "not_applicable"
            assert (
                c.execute(
                    "SELECT document FROM cve.v5_revision_documents "
                    "WHERE identity=%s AND document_present",
                    (identity,),
                ).fetchone()["document"]
                == raw
            )
            assert not c.execute(
                "SELECT 1 FROM cve.enrichment_assertions a JOIN cve.enrichment_revisions e "
                "ON e.id=a.enrichment_revision_id WHERE e.identity=%s",
                (identity,),
            ).fetchone()
    finally:
        await importer.transport.close()
        await importer.database.close()
        await findings.matcher.database.close()
        await findings.database.close()
