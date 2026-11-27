"""Run every Python test in sequential sessions so disposable Docker labs are released."""

import argparse
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from scripts.testing.source import identity

ROOT = Path(__file__).resolve().parents[2]


def groups() -> list[tuple[str, list[str]]]:
    """Cover every module once with fresh state for each integration laboratory."""
    batches: dict[str, list[str]] = defaultdict(list)
    for path in sorted((ROOT / "tests").rglob("test_*.py")):
        relative = path.relative_to(ROOT)
        parts = relative.parts
        key = parts[1] if parts[1] == "unit" else str(relative.with_suffix(""))
        batches[key].append(str(relative))
    # Release packaging consumes the evidence from the preceding native suites.
    return sorted(
        batches.items(), key=lambda item: (item[0].startswith("tests/deployment/"), item[0])
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--only", nargs="*", help="Explicit batch names for a partial campaign")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--exclude-deployment", action="store_true")
    parser.add_argument("--shard", help="Deterministic batch partition, INDEX/COUNT (zero-based)")
    args = parser.parse_args()
    batches = groups()
    if args.only:
        unknown = set(args.only) - {key for key, _ in batches}
        if unknown:
            parser.error("Unknown batches: " + ", ".join(sorted(unknown)))
        batches = [(key, paths) for key, paths in batches if key in args.only]
    if args.exclude_deployment:
        batches = [
            (key, paths) for key, paths in batches if not key.startswith("tests/deployment/")
        ]
    expected = [key for key, _ in batches]
    if args.shard:
        index, count = (int(part) for part in args.shard.split("/"))
        if not 0 <= index < count <= 32:
            parser.error("Invalid shard")
        batches = [batch for number, batch in enumerate(batches) if number % count == index]
    if args.list:
        print("\n".join(key for key, _ in batches))
        return 0
    output = args.output or ROOT / ".runtime/test-reports" / (
        "campaign-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    environment = {
        **os.environ,
        "CVE_TEST_COMPACT_NETWORKS": "1",
        "CVE_ENV_FILE": os.environ.get("CVE_ENV_FILE", "configuration/examples/development.env"),
    }
    source = identity(ROOT)
    results = []
    failed = False
    evidence_collected = False
    for key, paths in batches:
        if (
            not args.only
            and not args.shard
            and key.startswith("tests/deployment/")
            and not evidence_collected
        ):
            from scripts.testing.evidence import collect

            collect(output)
            evidence_collected = True
        name = key.replace("/", "-")
        report = output / (name + ".xml")
        print(key, flush=True)
        with (output / (name + ".log")).open("x") as log:
            os.chmod(log.name, 0o600)
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-m",
                    "",
                    *paths,
                    "--tb=short",
                    "--junitxml=" + str(report),
                ],
                cwd=ROOT,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
        counts = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
        if report.exists():
            for suite in ET.parse(report).getroot().iter("testsuite"):
                for field in counts:
                    counts[field] += int(suite.get(field, "0"))
        failed |= process.returncode != 0 or counts["skipped"] > 0 or counts["tests"] == 0
        results.append({"batch": key, "returncode": process.returncode, **counts})
        (output / "summary.json").write_text(
            json.dumps(
                {
                    "complete_selection": not args.only
                    and not args.shard
                    and not args.exclude_deployment,
                    "source": source,
                    "source_unchanged": identity(ROOT) == source,
                    "shard": args.shard,
                    "expected_batches": expected,
                    "selected_batches": [name for name, _ in batches],
                    "missing_batches": [
                        name for name, _ in batches if name not in {r["batch"] for r in results}
                    ],
                    "results": results,
                },
                indent=2,
            )
            + "\n"
        )
        if process.returncode < 0:
            return 1
    return int(failed or identity(ROOT) != source)


if __name__ == "__main__":
    raise SystemExit(main())
