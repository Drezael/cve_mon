"""Verify a complete campaign using explicit, traceable whole-batch reruns."""

import argparse
import hashlib
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

from scripts.testing.campaign import ROOT, groups


def inspect(report: Path) -> tuple[dict[str, int], set[tuple[str, str]]]:
    root = ET.parse(report).getroot()
    counts = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    identities = set()
    for case in root.iter("testcase"):
        identity = (case.get("classname", ""), case.get("name", ""))
        if identity in identities:
            raise ValueError("Duplicate testcase: " + str(identity))
        identities.add(identity)
        counts["tests"] += 1
        for field, tag in (("failures", "failure"), ("errors", "error"), ("skipped", "skipped")):
            counts[field] += int(case.find(tag) is not None)
    if not identities:
        raise ValueError("Empty test report: " + str(report))
    return counts, identities


def reconcile(campaign: Path, overrides: Path, output: Path) -> None:
    summary = json.loads((campaign / "summary.json").read_text())
    results = {item["batch"]: item for item in summary["results"]}
    expected = {key for key, _ in groups()}
    changes = json.loads(overrides.read_text())
    if (
        not summary["complete_selection"]
        or results.keys() != expected
        or len(results) != len(summary["results"])
        or changes.keys() - expected
    ):
        raise ValueError("A complete, unique campaign selection is required")
    selected = []
    provenance = []
    for key, item in results.items():
        original = campaign / (key.replace("/", "-") + ".xml")
        counts, identities = inspect(original)
        if any(counts[field] != item[field] for field in counts):
            raise ValueError("Campaign summary disagrees with JUnit: " + key)
        report = original
        if key in changes:
            change = changes[key]
            report = ROOT / change["rerun"]
            if (ROOT / change["original"]).resolve() != original.resolve():
                raise ValueError("Override belongs to a different campaign: " + key)
            for label, path in (("original", original), ("rerun", report)):
                if hashlib.sha256(path.read_bytes()).hexdigest() != change[label + "_sha256"]:
                    raise ValueError("Changed report: " + str(path))
            counts, rerun_identities = inspect(report)
            if identities != rerun_identities or not change["reason"].strip():
                raise ValueError("A justified whole-batch rerun is required: " + key)
            provenance.append({"batch": key, **change})
        elif item["returncode"]:
            raise ValueError("Unresolved test process failure: " + key)
        if any(counts[field] for field in ("failures", "errors", "skipped")):
            raise ValueError("Unresolved nonpassing tests: " + key)
        selected.append((report, original.name, {"batch": key, "returncode": 0, **counts}))
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    for report, name, _ in selected:
        shutil.copyfile(report, output / name)
        (output / name).chmod(0o600)
    (output / "summary.json").write_text(
        json.dumps(
            {"complete_selection": True, "results": [item for _, _, item in selected]}, indent=2
        )
        + "\n"
    )
    (output / "provenance.json").write_text(
        json.dumps({"campaign": str(campaign.resolve()), "overrides": provenance}, indent=2) + "\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("overrides", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    reconcile(args.campaign, args.overrides, args.output)


if __name__ == "__main__":
    main()
