"""Recorded technical queue baseline: mixed history, bounded pool and starvation prevention."""

import asyncio
import json
import time
from uuid import uuid4

import pytest
from cve_common.jobs.repository import JobRepository

from scripts.database import manage as db
from tests.automation.integration.conftest import Lab

pytestmark = pytest.mark.automation


async def test_queue_baseline_and_aging(worker: JobRepository, automation_lab: Lab) -> None:
    prefix = "benchmark-" + uuid4().hex
    oldest = uuid4()
    with db.connect(automation_lab.config, "cve_migrator") as connection:
        connection.execute("SET ROLE postgres_owner")
        connection.execute(
            """INSERT INTO automation.jobs(
         job_type,runtime_version,creator_role,request_fingerprint,
         correlation_id,payload,idempotency_key,actor_reference,status,priority,finished_at)
         SELECT 'technical.success',1,'api_security',sha256(g::text::bytea),
         gen_random_uuid(),'{"value":1}'::jsonb,
         %s||g,'benchmark',CASE WHEN g%%10=0 THEN 'queued' ELSE 'succeeded' END,g%%201-100,
         CASE WHEN g%%10=0 THEN NULL ELSE clock_timestamp() END FROM generate_series(1,2250) g""",
            (prefix,),
        )
        connection.execute(
            """INSERT INTO automation.jobs(
        id,job_type,runtime_version,creator_role,request_fingerprint,
        correlation_id,payload,idempotency_key,actor_reference,status,priority,scheduled_at)
        VALUES (%s,'technical.success',1,'api_security',sha256('oldest'::bytea),
        gen_random_uuid(),'{"value":1}',
        %s,'benchmark','queued',-100,clock_timestamp()-interval '90 seconds')""",
            (oldest, prefix + "oldest"),
        )
        connection.execute("ANALYZE automation.jobs")
        plan = connection.execute(
            "EXPLAIN (FORMAT JSON,ANALYZE,BUFFERS) SELECT id FROM automation.j"
            "obs WHERE runtime_version=1 AND job_type='technical.success' AND "
            "status IN ('queued','retry_pending') AND scheduled_at<=clock_time"
            "stamp() ORDER BY priority DESC,scheduled_at,id LIMIT 1"
        ).fetchone()
        assert plan is not None
        query_plan = plan["QUERY PLAN"]
    first = await worker.claim(uuid4(), 5)
    assert first is not None and first.id == oldest
    await worker.finish(first, "succeeded")
    ids = []
    started = time.monotonic()

    async def consumer() -> None:
        for _ in range(20):
            job = await worker.claim(uuid4(), 5)
            assert job is not None
            ids.append(str(job.id))
            assert await worker.finish(job, "succeeded")

    await asyncio.gather(*(consumer() for _ in range(8)))
    duration = time.monotonic() - started
    assert len(ids) == 160 and len(set(ids)) == 160
    report = {
        "history_rows": 2250,
        "active_seed_rows": 225,
        "claims": 160,
        "claimers": 8,
        "pool_limit": worker.database.settings.pool_size,
        "seconds": duration,
        "claims_per_second": 160 / duration,
        "starvation_oldest_low_priority_claimed_first": True,
        "query_plan": query_plan,
    }
    path = automation_lab.config.root / ".runtime/test-reports/phase-07-performance.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    assert duration < 30
