"""Real SIGKILL/SIGTERM processes, persistent side effects, deadlines and exhausted retries."""

import asyncio
import json
import signal
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from cve_common.jobs.errors import ErrorCode
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.models import Job
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import WorkerSettings
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from scripts.database import manage as db
from tests.automation.integration.conftest import Lab
from tests.automation.integration.test_jobs import enqueue

pytestmark = [pytest.mark.automation, pytest.mark.security]


@pytest.mark.parametrize(
    "mode,terminate", [("before_handler", False), ("after_effect", False), ("after_effect", True)]
)
async def test_process_crash_and_graceful_signal(
    producer: JobRepository, worker: JobRepository, automation_lab: Lab, mode: str, terminate: bool
) -> None:
    job = await enqueue(producer, job_type="technical.slow")
    config = WorkerSettings(
        service_name="cve-test-worker",
        app_env="test",
        database=automation_lab.settings("importer"),
        lease_seconds=0.6,
        heartbeat_seconds=0.1,
        poll_seconds=0.05,
        shutdown_seconds=0.2,
    )
    script = Path(__file__).resolve().parents[1] / "fixtures/worker_process.py"
    process = subprocess.Popen(
        [sys.executable, str(script)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None
    process.stdin.write(json.dumps({"settings": config.model_dump(mode="json"), "mode": mode}))
    process.stdin.close()
    old = None
    try:
        for _ in range(100):
            with db.connect(automation_lab.config, "cve_migrator") as connection:
                connection.execute("SET ROLE postgres_owner")
                row = connection.execute(
                    "SELECT * FROM automation.jobs WHERE id=%s", (job.id,)
                ).fetchone()
                effect = connection.execute(
                    "SELECT id FROM automation.test_effects WHERE id=%s", (job.id,)
                ).fetchone()
                if row and row["status"] == "running" and (mode == "before_handler" or effect):
                    old = Job.model_validate(row)
                    break
            if process.poll() is not None:
                assert process.stderr is not None
                raise AssertionError("Controlled process stopped: " + process.stderr.read())
            await asyncio.sleep(0.05)
        assert old is not None
        process.send_signal(signal.SIGTERM if terminate else signal.SIGKILL)
        process.wait(timeout=5)
        assert process.returncode == (0 if terminate else -signal.SIGKILL)
        if not terminate:
            await asyncio.sleep(0.7)
            await worker.recover()
        await asyncio.sleep(0.25)
        assert not await worker.finish(old, "succeeded")
        fresh = None
        for _ in range(100):
            candidate = await worker.claim(uuid4(), 2)
            if candidate is None:
                await asyncio.sleep(0.05)
                continue
            if candidate.id == job.id:
                fresh = candidate
                break
            await worker.finish(candidate, "succeeded")
        assert fresh is not None and fresh.fencing_token > old.fencing_token
        context = ExecutionContext(
            worker, fresh, worker.registry.get(fresh.job_type, 1), asyncio.Event()
        )

        async def effect_once(session: AsyncSession) -> None:
            await session.execute(
                text(
                    "INSERT INTO automation.test_effects(id,value) VALUES (:id,1) ON C"
                    "ONFLICT DO NOTHING"
                ),
                {"id": job.id},
            )

        await context.complete(effect_once)
        with db.connect(automation_lab.config, "cve_migrator") as connection:
            connection.execute("SET ROLE postgres_owner")
            row = connection.execute(
                "SELECT count(*) AS n FROM automation.test_effects WHERE id=%s", (job.id,)
            ).fetchone()
            assert row is not None and row["n"] == 1
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stderr:
            process.stderr.close()


async def test_retry_limit_permanent_deadletter_and_deadline(
    producer: JobRepository, worker: JobRepository, automation_lab: Lab
) -> None:
    target = await enqueue(producer, job_type="technical.retry")
    current = None
    for _ in range(100):
        candidate = await worker.claim(uuid4(), 2)
        if candidate is None:
            await asyncio.sleep(0.05)
            continue
        if candidate.id == target.id:
            current = candidate
            break
        await worker.finish(candidate, "succeeded")
    assert current is not None
    for number in range(1, 4):
        assert current.attempts == number
        assert await worker.finish(current, "retry", ErrorCode.TEMPORARY)
        if number < 3:
            await asyncio.sleep(0.25)
            current = await worker.claim(uuid4(), 2)
            assert current is not None and current.id == target.id
    with db.connect(automation_lab.config, "cve_migrator") as connection:
        connection.execute("SET ROLE postgres_owner")
        row = connection.execute(
            "SELECT status,attempts FROM automation.jobs WHERE id=%s", (target.id,)
        ).fetchone()
        assert row is not None and row["status"] == "failed" and row["attempts"] == 3
        now = connection.execute("SELECT clock_timestamp() AS t").fetchone()
        assert now is not None
        deadline = now["t"] + timedelta(seconds=0.25)
    expired = await enqueue(producer, deadline=deadline)
    await asyncio.sleep(0.3)
    await worker.recover()
    with db.connect(automation_lab.config, "cve_migrator") as connection:
        connection.execute("SET ROLE postgres_owner")
        row = connection.execute(
            "SELECT status,attempts FROM automation.jobs WHERE id=%s", (expired.id,)
        ).fetchone()
        assert row is not None and row["status"] == "timed_out" and row["attempts"] == 0
