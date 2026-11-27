"""Exact, expiring image findings with reviewed configuration evidence; no severity exclusions."""

import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from scripts.hardening.supply_chain import gate


def apply(
    report: dict[str, Any],
    reference: str,
    root: Path,
    *,
    today: date | None = None,
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    findings = gate(report)
    path = root / "infrastructure/image-reviews.json"
    if not path.is_file():
        return findings, []
    policy = json.loads(path.read_text())
    if policy["version"] != 1:
        raise ValueError("Unsupported image review format")
    now = today or datetime.now(UTC).date()
    entries = [entry for entry in policy["reviews"] if entry["image"] == reference]
    if not entries:
        return findings, []
    evidence = policy["evidence_hashes"]
    if not evidence or any(
        not (root / name).is_file()
        or hashlib.sha256((root / name).read_bytes()).hexdigest() != digest["sha256"]
        for name, digest in evidence.items()
    ):
        raise ValueError("Image review evidence changed; reassess before accepting findings")
    targets = {
        item["Target"]: item["Type"] if item["Class"] == "os-pkgs" else item["Target"]
        for item in report["Results"]
        if item.get("Class") in {"os-pkgs", "lang-pkgs"}
    }
    blocked, accepted = [], []
    for finding in findings:
        identity = {field: finding[field] for field in ("id", "package", "installed", "severity")}
        identity["target"] = targets.get(finding["target"], finding["target"])
        matches = [entry for entry in entries if entry["finding"] == identity]
        if not matches:
            blocked.append(finding)
            continue
        if len(matches) != 1:
            raise ValueError("Duplicate image review")
        entry = matches[0]
        if (
            not entry["rationale"].strip()
            or not entry["evidence"]
            or any(name not in evidence for name in entry["evidence"])
            or date.fromisoformat(entry["expires"]) < now
            or entry["disposition"] not in {"not_affected", "false_positive"}
        ):
            raise ValueError("Expired or incomplete image review: " + finding["id"])
        accepted.append({**finding, "review": entry})
    return blocked, accepted
