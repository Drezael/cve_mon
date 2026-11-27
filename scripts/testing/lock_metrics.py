"""Summarize observed read/mutation lock latency from allowlisted JSON logs."""

import argparse
import json
from pathlib import Path
from typing import Any


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    output = {}
    for mutation in (False, True):
        for event, key in (
            ("security_lock_acquired", "wait_seconds"),
            ("security_transaction_finished", "duration_ms"),
        ):
            values = sorted(
                float(r[key])
                for r in records
                if r.get("event") == event and r.get("mutation") is mutation and key in r
            )
            output[f"{'mutation' if mutation else 'read'}_{key}"] = (
                {
                    "samples": len(values),
                    "p95": values[max(0, (95 * len(values) + 99) // 100 - 1)],
                    "p99": values[max(0, (99 * len(values) + 99) // 100 - 1)],
                    "max": values[-1],
                }
                if values
                else {"samples": 0, "p95": None, "p99": None, "max": None}
            )
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            summarize(
                [
                    json.loads(line)
                    for line in args.log.read_text().splitlines()
                    if line.startswith("{")
                ]
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
