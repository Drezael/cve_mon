"""Native document reads preserve matching semantics without persisting normalized copies."""

from uuid import uuid4

import pytest
from cve_common.v5 import project
from cve_enricher.normalize import normalize
from cve_matcher.engine import evaluate, source_keys

from tests.cve_importer.fixtures import cve


@pytest.mark.parametrize("state", ["PUBLISHED", "REJECTED"])
def test_native_projection_matches_historical_v5_semantics(state: str) -> None:
    raw = cve(state=state)
    revision = uuid4()
    if state == "PUBLISHED":
        product = {
            "vendor": "fixture",
            "product": "example",
            "defaultStatus": "unaffected",
            "versions": [
                {
                    "version": "1.0.0",
                    "lessThan": "2.0.0",
                    "versionType": "semver",
                    "status": "affected",
                    "changes": [{"at": "1.5.0", "status": "unaffected"}],
                }
            ],
        }
        raw["containers"]["cna"]["affected"] = [product]
        raw["containers"]["adp"] = [
            {
                "providerMetadata": {"orgId": "supplemental"},
                "affected": [product],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                        }
                    }
                ],
            }
        ]
    previous = normalize(
        "CVE-2026-12345",
        [
            {
                "source_id": "cve_list",
                "external_id": "CVE-2026-12345",
                "revision_id": revision,
                "original_json": raw,
                "identifiers": ["CVE-2026-12345"],
                "present": True,
            }
        ],
        {"status": "unknown"},
    )
    native = project("CVE-2026-12345", raw, revision, True, include_cvss=True)
    for key in ("lifecycle", "affected", "cvss"):
        assert native[key] == previous[key]
    assert source_keys(native["affected"]) == source_keys(previous["affected"])
    for version in ("1.2.0", "1.6.0", "3.0.0"):
        component = {
            "id": "fixture",
            "kind": "package",
            "product": "example",
            "name": "example",
            "version": version,
            "vendor": "fixture",
        }
        assert evaluate(native, [component], {}) == evaluate(previous, [component], {})


def test_removed_document_is_excluded_without_erasing_its_original() -> None:
    raw = cve()
    value = project("CVE-2026-12345", raw, uuid4(), False)
    assert value["lifecycle"]["value"] == "withdrawn"
    assert all(not a["matching_usable"] for a in value["affected"])
    assert raw["cveMetadata"]["state"] == "PUBLISHED"


def test_invalid_cvss_does_not_become_a_priority_signal() -> None:
    raw = cve()
    raw["containers"]["cna"]["metrics"] = [
        {
            "cvssV3_1": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 1,
            }
        }
    ]
    assert project("CVE-2026-12345", raw, uuid4(), True)["cvss"] == []
    assessments = project("CVE-2026-12345", raw, uuid4(), True, include_cvss=True)["cvss"]
    assert assessments[0]["validation_status"] == "score_mismatch"
    assert not assessments[0]["is_preferred"]
