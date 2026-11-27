"""Derive release-candidate regression evidence from actual campaign JUnit reports."""

import argparse
import copy
import json
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

from scripts.hardening import manage
from scripts.testing.campaign import ROOT, groups


def collect(campaign: Path) -> dict[str, int]:
    summary = json.loads((campaign / "summary.json").read_text())
    from scripts.testing.source import identity

    if summary.get("source") != identity(ROOT) or not summary.get("source_unchanged"):
        raise ValueError("Campaign source identity no longer matches current sources")
    if not summary["complete_selection"]:
        raise ValueError("Full campaign selection required")
    expected = {key: paths for key, paths in groups() if not key.startswith("tests/deployment/")}
    results = {item["batch"]: item for item in summary["results"]}
    if expected.keys() - results.keys():
        raise ValueError("Native regression campaign has not completed")
    records = []
    counts = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    for key, paths in expected.items():
        item = results[key]
        report = campaign / (key.replace("/", "-") + ".xml")
        root = ET.parse(report).getroot()
        for field in counts:
            counts[field] += item[field]
        if item["returncode"] and not (item["failures"] or item["errors"]):
            raise ValueError("Incomplete native test process: " + key)
        records.append((paths, root))
    reports = ROOT / ".runtime/test-reports"
    for name, (paths, _) in {**manage.SUITES, **manage.IMAGE_SUITES}.items():
        target = ET.Element("testsuites")
        for modules, root in records:
            if any(
                Path(module) == Path(prefix) or Path(prefix) in Path(module).parents
                for module in modules
                for prefix in paths
            ):
                for suite in root.iter("testsuite"):
                    target.append(copy.deepcopy(suite))
        if not list(target.iter("testcase")):
            raise ValueError("No actual campaign evidence for " + name)
        ET.ElementTree(target).write(reports / ("phase-23-" + name + ".xml"), encoding="utf-8")
    value = {
        "checked_at": datetime.now(UTC).isoformat(),
        "campaign": str(campaign.resolve()),
        "scope": "all non-deployment Python modules; deployment candidates follow separately",
        **counts,
    }
    (reports / "phase-23-test-summary.json").write_text(json.dumps(value, indent=2) + "\n")
    # Preserve a real NO_GO decision when broader release evidence is unavailable.
    # Staging a local candidate never constitutes production authorization.
    try:
        manage.acceptance()
    except ValueError as error:
        if str(error) != "Phase-23 acceptance requirements not satisfied":
            raise
        decision = json.loads((reports / "phase-23-acceptance.json").read_text())
        if decision["decision"] != "NO_GO" or not decision["blocking"]:
            raise
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    args = parser.parse_args()
    print(json.dumps(collect(args.campaign)))


if __name__ == "__main__":
    main()
