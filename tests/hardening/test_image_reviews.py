"""Reviewed findings remain bound to exact artifacts, versions, paths, dates and code."""

import hashlib
import json
from datetime import date
from pathlib import Path

import pytest

from scripts.hardening.image_reviews import apply


def fixture(root: Path) -> tuple[dict[str, object], str]:
    reference = "vendor:1@sha256:" + "a" * 64
    (root / "infrastructure").mkdir()
    (root / "compose.yml").write_text("closed fixture")
    policy = {
        "version": 1,
        "evidence_hashes": {
            "compose.yml": {"sha256": hashlib.sha256(b"closed fixture").hexdigest()}
        },
        "reviews": [
            {
                "image": reference,
                "finding": {
                    "id": "TEST-1",
                    "package": "test",
                    "installed": "1",
                    "severity": "HIGH",
                    "target": "usr/bin/utility",
                },
                "disposition": "not_affected",
                "expires": "2026-12-23",
                "rationale": "Fixture utility has no affected network entry point",
                "evidence": ["compose.yml"],
            }
        ],
    }
    (root / "infrastructure/image-reviews.json").write_text(json.dumps(policy))
    return {
        "Results": [
            {
                "Target": "usr/bin/utility",
                "Class": "lang-pkgs",
                "Type": "gobinary",
                "Packages": [{}],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "TEST-1",
                        "PkgName": "test",
                        "InstalledVersion": "1",
                        "Severity": "HIGH",
                        "FixedVersion": "2",
                    }
                ],
            }
        ]
    }, reference


def test_review_matches_only_the_exact_finding(tmp_path: Path) -> None:
    report, image = fixture(tmp_path)
    blocked, reviewed = apply(report, image, tmp_path, today=date(2026, 11, 23))
    assert not blocked and len(reviewed) == 1
    assert apply(report, image + "changed", tmp_path)[0]


@pytest.mark.parametrize("mutation", ["version", "id", "severity", "path"])
def test_changed_findings_still_block(tmp_path: Path, mutation: str) -> None:
    report, image = fixture(tmp_path)
    result = report["Results"][0]  # type: ignore[index]
    finding = result["Vulnerabilities"][0]
    if mutation == "path":
        result["Target"] = "usr/bin/other"
    else:
        field = {"version": "InstalledVersion", "id": "VulnerabilityID", "severity": "Severity"}
        finding[field[mutation]] = "CRITICAL" if mutation == "severity" else "new"
    assert apply(report, image, tmp_path, today=date(2026, 11, 23))[0]


@pytest.mark.parametrize("mutation", ["expired", "evidence", "rationale"])
def test_invalid_review_fails_closed(tmp_path: Path, mutation: str) -> None:
    report, image = fixture(tmp_path)
    today = date(2026, 11, 23)
    if mutation == "expired":
        today = date(2027, 1, 1)
    elif mutation == "evidence":
        (tmp_path / "compose.yml").write_text("changed network boundary")
    else:
        file = tmp_path / "infrastructure/image-reviews.json"
        policy = json.loads(file.read_text())
        policy["reviews"][0]["rationale"] = ""
        file.write_text(json.dumps(policy))
    with pytest.raises(ValueError):
        apply(report, image, tmp_path, today=today)
