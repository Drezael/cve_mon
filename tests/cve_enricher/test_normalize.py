"""Independent published CVSS examples and pure source policy boundaries."""

from typing import Any
from uuid import uuid4

import pytest
from cve_enricher.normalize import metric, normalize

from tests.cve_importer import fixtures as f

pytestmark = [pytest.mark.cve_enricher, pytest.mark.domain]


def row(source: str, raw: dict[str, Any], identity: str = "CVE-2026-12345") -> dict[str, Any]:
    return {
        "source_id": source,
        "external_id": identity,
        "revision_id": uuid4(),
        "original_json": raw,
        "identifiers": [identity],
    }


@pytest.mark.parametrize(
    "version,vector,score",
    [
        ("2.0", "AV:N/AC:L/Au:N/C:C/I:C/A:C", 10),
        ("3.0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    ],
)
def test_cvss_published_examples(version: str, vector: str, score: float) -> None:
    value = metric(
        {"version": version, "vectorString": vector, "baseScore": score}, row("nvd", {}), "/metrics"
    )
    assert value["validation_status"] == "valid" and value["base_score"] == score


@pytest.mark.parametrize(
    "changes,status",
    [
        ({"version": "5.0"}, "unsupported_version"),
        ({"vectorString": "CVSS:3.1/AV:N"}, "invalid_vector"),
        ({"baseScore": 1}, "score_mismatch"),
        ({"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:Z"}, "invalid_vector"),
        ({"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L"}, "invalid_vector"),
        ({"baseScore": None}, "valid"),
    ],
)
def test_cvss_invalid_incomplete_or_mismatch(changes: dict[str, Any], status: str) -> None:
    value = {
        "version": "3.1",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "baseScore": 9.8,
    }
    value.update(changes)
    assert metric(value, row("nvd", {}), "/metrics")["validation_status"] == status


def test_ambiguous_advisory_keeps_cves_independent() -> None:
    value = f.osv()
    r = row("osv", value, value["id"])
    r["identifiers"] = [value["id"], *value["aliases"]]
    result = normalize("CVE-2026-12345", [r], {"status": "unknown"})
    assert len(result["relations"]) == 2
    assert all(r["validation_status"] == "ambiguous" for r in result["relations"])
    assert all(not e["matching_usable"] for e in result["affected"])
    assert result["affected"][0]["value"]["ranges"] == value["affected"][0]["ranges"]


def test_advisory_without_cve_and_withdrawal() -> None:
    value = f.osv(withdrawn=True)
    value["aliases"] = []
    r = row("osv", value, value["id"])
    result = normalize(value["id"], [r], {"status": "unknown"})
    assert result["identity_kind"] == "advisory" and not result["relations"]
    assert result["lifecycle"]["value"] == "withdrawn"
    assert all(not e["matching_usable"] for e in result["affected"])


def test_official_status_wins_newer_nvd_and_determinism() -> None:
    rows = [row("cve_list", f.cve(state="REJECTED")), row("nvd", f.nvd())]
    first = normalize("CVE-2026-12345", rows, {"status": "unknown"})
    assert normalize("CVE-2026-12345", list(reversed(rows)), {"status": "unknown"}) == first
    assert first["lifecycle"]["value"] == "rejected"
    assert any(c["kind"] == "source_status" for c in first["conflicts"])


def test_nvd_configuration_tree_and_ubuntu_fix_unchanged() -> None:
    n = f.nvd()
    n["configurations"] = [
        {
            "operator": "AND",
            "negate": True,
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:a:example:example:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "1.0",
                        }
                    ],
                }
            ],
        }
    ]
    u = f.ubuntu()
    result = normalize("CVE-2026-12345", [row("nvd", n), row("ubuntu", u)], {"status": "unknown"})
    values = {e["kind"]: e["value"] for e in result["affected"]}
    assert values["nvd_configuration_logic"] == n["configurations"]
    assert values["ubuntu_packages"] == u["packages"]
    assert "1:2.0-1ubuntu1" in str(values["ubuntu_packages"])


def test_missing_information_is_unknown_not_zero() -> None:
    value = normalize("CVE-2026-12345", [], {"status": "unknown"})
    assert value["lifecycle"]["value"] == "unknown" and value["cvss"] == []
    assert value["primary_description"] is None and value["affected"] == []


def test_preferred_cvss_uses_version_policy_without_cross_version_conflict() -> None:
    value = f.cve()
    value["containers"]["cna"]["metrics"] = [
        {
            "cvssV3_1": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
            }
        },
        {
            "cvssV4_0": {
                "version": "4.0",
                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "baseScore": 9.3,
            }
        },
    ]
    result = normalize("CVE-2026-12345", [row("cve_list", value)], {"status": "unknown"})
    assert [m["cvss_version"] for m in result["cvss"] if m["is_preferred"]] == ["4.0"]
    assert not any(c["kind"] == "cvss_disagreement" for c in result["conflicts"])


def test_primary_cna_description_precedes_supplemental_language() -> None:
    value = f.cve()
    value["containers"]["cna"]["descriptions"] = [{"lang": "fr", "value": "Description officielle"}]
    result = normalize(
        "CVE-2026-12345", [row("cve_list", value), row("nvd", f.nvd())], {"status": "unknown"}
    )
    assert result["primary_description"]["value"] == "Description officielle"
    assert not any(c["kind"] == "description_disagreement" for c in result["conflicts"])


def test_enrichment_result_contract(repository_root: Any) -> None:
    import json

    from jsonschema import Draft202012Validator

    schema = json.loads((repository_root / "contracts/cve/enrichment-v1.schema.json").read_text())
    result = normalize("CVE-2026-12345", [row("cve_list", f.cve())], {"status": "unknown"})
    Draft202012Validator(schema).validate(result)


@pytest.mark.parametrize(
    "suffix,nomenclature,context",
    [
        ("", "CVSS-B", "9.3"),
        ("/E:U", "CVSS-BT", "8.1"),
        ("/MVI:L", "CVSS-BE", "8.8"),
        ("/E:U/MVI:L", "CVSS-BTE", "6.9"),
    ],
)
def test_cvss4_base_and_supplied_context_scores_remain_distinct(
    suffix: str, nomenclature: str, context: str
) -> None:
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" + suffix
    assessment = {"version": "4.0", "vectorString": vector, "baseScore": 9.3}
    if "MVI" in suffix:
        assessment["environmentalScore"] = float(context)
    elif "/E:" in suffix:
        assessment["threatScore"] = float(context)
    result = metric(assessment, row("cve_list", {}), "/metrics")
    assert result["validation_status"] == "valid"
    assert result["base_score"] == 9.3 and result["context_score"] == context
    assert result["score_nomenclature"] == nomenclature
