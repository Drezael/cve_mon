"""Per-domain regression floors for the standard suite, separate from integration evidence."""

import argparse
import json
from pathlib import Path
from typing import Any


def check(report: dict[str, Any], policy: dict[str, Any]) -> dict[str, dict[str, float]]:
    results = {}
    for name, scope in policy["scopes"].items():
        summaries = [
            data["summary"]
            for path, data in report["files"].items()
            if any(path.startswith(prefix) for prefix in scope["paths"])
        ]
        statements = sum(s["num_statements"] for s in summaries)
        branches = sum(s.get("num_branches", 0) for s in summaries)
        if not summaries or not statements:
            raise ValueError("Missing coverage scope: " + name)
        lines = 100 * sum(s["covered_lines"] for s in summaries) / statements
        branch = 100 * sum(s.get("covered_branches", 0) for s in summaries) / max(1, branches)
        results[name] = {"lines": round(lines, 2), "branches": round(branch, 2)}
        if lines < scope["minimum_lines"] or branch < scope["minimum_branches"]:
            raise ValueError("Coverage regression in " + name + ": " + str(results[name]))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--policy", type=Path, default=Path("configuration/quality/coverage.json"))
    args = parser.parse_args()
    print(
        json.dumps(
            check(json.loads(args.report.read_text()), json.loads(args.policy.read_text())),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
