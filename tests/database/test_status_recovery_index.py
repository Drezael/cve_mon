"""Failure resolution must use a selective index even for legacy job rows."""

import json
from typing import Any

import psycopg
import pytest

from tests.database.helpers import required_row

pytestmark = pytest.mark.database


def test_resolved_failure_lookup_stays_indexed_without_runtime_filter(
    owner: psycopg.Connection[dict[str, Any]],
) -> None:
    owner.execute(
        "INSERT INTO automation.jobs(job_type,status,idempotency_key,finished_at) "
        "SELECT 'status.collect','succeeded','status-cache-plan:'||g,clock_timestamp() "
        "FROM generate_series(1,3000) g"
    )
    failed = required_row(
        owner.execute(
            "INSERT INTO automation.jobs(job_type,status,idempotency_key,finished_at) "
            "VALUES('status.collect','failed','status-cache-failed',clock_timestamp()) RETURNING id"
        )
    )["id"]
    assert required_row(
        owner.execute("SELECT automation.job_failure_unresolved(%s) AS v", (failed,))
    )["v"]
    plan = required_row(
        owner.execute(
            "EXPLAIN (FORMAT JSON) SELECT 1 FROM automation.jobs old "
            "JOIN automation.jobs recovered ON recovered.job_type=old.job_type "
            "WHERE old.id=%s AND recovered.status='succeeded' "
            "AND recovered.finished_at>old.finished_at",
            (failed,),
        )
    )["QUERY PLAN"]
    assert "jobs_recovered_type_time" in json.dumps(plan)
    owner.execute(
        "INSERT INTO automation.jobs(job_type,status,idempotency_key,finished_at) "
        "VALUES('status.collect','succeeded','status-cache-recovered',clock_timestamp())"
    )
    assert not required_row(
        owner.execute("SELECT automation.job_failure_unresolved(%s) AS v", (failed,))
    )["v"]
