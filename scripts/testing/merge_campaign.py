"""Verify all source-bound non-deployment shards before generating release evidence."""

import argparse
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from scripts.testing.campaign import ROOT, groups
from scripts.testing.source import identity


def merge(inputs: Path, output: Path) -> None:
    source = identity(ROOT)
    expected = {key for key, _ in groups() if not key.startswith("tests/deployment/")}
    results: dict[str, Any] = {}
    manifests = sorted(inputs.rglob("summary.json"))
    if not manifests:
        raise ValueError("Campaign shards missing")
    output.mkdir(parents=True, exist_ok=False)
    for manifest in manifests:
        summary = json.loads(manifest.read_text())
        if (
            summary.get("source") != source
            or not summary.get("source_unchanged")
            or summary.get("missing_batches")
        ):
            raise ValueError("Incomplete or stale campaign shard")
        for result in summary["results"]:
            key = result["batch"]
            if key in results or key not in expected:
                raise ValueError("Duplicate or unexpected batch")
            if (
                any(result[field] for field in ("returncode", "failures", "errors", "skipped"))
                or not result["tests"]
            ):
                raise ValueError("Failed campaign batch: " + key)
            report = manifest.parent / (key.replace("/", "-") + ".xml")
            if not report.is_file():
                raise ValueError("Missing batch JUnit")
            document = ET.parse(report).getroot()
            actual = {
                field: sum(int(suite.get(field, "0")) for suite in document.iter("testsuite"))
                for field in ("tests", "failures", "errors", "skipped")
            }
            if any(actual[field] != result[field] for field in actual):
                raise ValueError("JUnit and campaign summary disagree")
            shutil.copyfile(report, output / report.name)
            results[key] = result
    missing = sorted(expected - results.keys())
    (output / "summary.json").write_text(
        json.dumps(
            {
                "source": source,
                "source_unchanged": True,
                "complete_selection": not missing,
                "missing_batches": missing,
                "results": list(results.values()),
            },
            indent=2,
        )
        + "\n"
    )
    if missing:
        raise ValueError("Mandatory campaign batches missing: " + ", ".join(missing))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    merge(args.inputs, args.output)


if __name__ == "__main__":
    main()
