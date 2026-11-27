"""Read-only sizing and synthetic lock-coordination evidence on a disposable database."""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from scripts.database import manage as db
from scripts.database.capacity import collect
from scripts.infrastructure.manage import Config
from scripts.testing.lock_metrics import summarize

pytestmark = pytest.mark.database


def test_readonly_capacity_and_lock_smoke(db_config: Config) -> None:
    with db.connect(db_config) as connection:
        capacity = collect(connection)
        mode = connection.execute("SHOW transaction_read_only").fetchone()
        assert mode is not None and mode["transaction_read_only"] == "on"
        assert capacity["counts"]["database_bytes"] > 0

    def sample(mutation: bool) -> list[dict[str, Any]]:
        with db.connect(db_config) as connection:
            start = time.perf_counter()
            function = "pg_advisory_xact_lock" if mutation else "pg_advisory_xact_lock_shared"
            connection.execute("SELECT " + function + "(909001)")
            acquired = time.perf_counter()
            connection.execute("SELECT pg_sleep(0.01)")
            return [
                {
                    "event": "security_lock_acquired",
                    "mutation": mutation,
                    "wait_seconds": acquired - start,
                },
                {
                    "event": "security_transaction_finished",
                    "mutation": mutation,
                    "duration_ms": 1000 * (time.perf_counter() - acquired),
                },
            ]

    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(sample, [False, False, False, True] * 5))
    report = Path(".runtime/test-reports/review-measurements.json")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(
            {
                "scope": "disposable empty database; synthetic lock smoke, not an API load budget",
                "capacity": capacity,
                "locks": summarize([r for v in values for r in v]),
            },
            indent=2,
        )
    )
    assert summarize([r for v in values for r in v])["mutation_wait_seconds"]["samples"] == 5
