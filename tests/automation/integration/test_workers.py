"""Actual handler tasks, heartbeats, failure isolation, cancellation and fenced transactions."""

import asyncio
from uuid import uuid4

import pytest
from cve_common.jobs.errors import ErrorCode, JobError, LeaseLost
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import JobDefinition, Registry
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker, WorkerSettings
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from scripts.database import manage as db
from tests.automation.integration.conftest import Lab, Value
from tests.automation.integration.test_jobs import enqueue

pytestmark = [pytest.mark.automation, pytest.mark.security]


async def test_worker_retries_and_failure_does_not_stop_loop(
    producer: JobRepository, worker: JobRepository, automation_lab: Lab
) -> None:
    count = 0

    async def controlled(context: ExecutionContext, payload: BaseModel) -> None:
        nonlocal count
        count += 1
        if context.job.attempts == 1:
            raise JobError(ErrorCode.TEMPORARY)

    registry = Registry()
    registry.register(JobDefinition("technical.retry", 1, Value, None, controlled, max_runtime=3))
    worker.registry = registry
    job = await enqueue(producer, job_type="technical.retry")
    settings = WorkerSettings(
        service_name="cve-test-worker",
        app_env="test",
        database=automation_lab.settings("importer"),
        lease_seconds=0.6,
        heartbeat_seconds=0.1,
        poll_seconds=0.05,
        shutdown_seconds=0.2,
    )
    runtime = Worker(worker, settings)
    stop = asyncio.Event()
    task = asyncio.create_task(runtime.run(stop))
    try:
        for _ in range(100):
            with db.connect(automation_lab.config, "cve_migrator") as connection:
                connection.execute("SET ROLE postgres_owner")
                row = connection.execute(
                    "SELECT status,attempts FROM automation.jobs WHERE id=%s", (job.id,)
                ).fetchone()
                if row and row["status"] == "succeeded":
                    assert row["attempts"] == 2
                    break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("Worker did not recover")
        assert count == 2 and runtime.healthy
        assert len(runtime.active) <= settings.concurrency
    finally:
        stop.set()
        await task


async def test_fenced_business_transaction_and_atomic_success(
    producer: JobRepository, worker: JobRepository, automation_lab: Lab
) -> None:
    job = await enqueue(producer)
    old = None
    for _ in range(50):
        candidate = await worker.claim(uuid4(), 0.2)
        if candidate is None:
            break
        if candidate.id == job.id:
            old = candidate
            break
        await worker.finish(candidate, "succeeded")
    assert old is not None
    context = ExecutionContext(worker, old, worker.registry.get(old.job_type, 1), asyncio.Event())
    identity = uuid4()
    await asyncio.sleep(0.25)
    with pytest.raises(LeaseLost):
        async with context.atomic() as session:
            await session.execute(
                text("INSERT INTO automation.test_effects VALUES (:id,1)"), {"id": identity}
            )
    await worker.recover()
    await asyncio.sleep(0.25)
    fresh = await worker.claim(uuid4(), 2)
    assert fresh is not None and fresh.id == old.id
    current = ExecutionContext(
        worker, fresh, worker.registry.get(fresh.job_type, 1), asyncio.Event()
    )

    async def effect(session: AsyncSession) -> None:
        await session.execute(
            text("INSERT INTO automation.test_effects VALUES (:id,1)"), {"id": identity}
        )

    await current.complete(effect)
    assert current.completed
    with db.connect(automation_lab.config, "cve_migrator") as connection:
        connection.execute("SET ROLE postgres_owner")
        row = connection.execute(
            "SELECT status FROM automation.jobs WHERE id=%s", (job.id,)
        ).fetchone()
        assert row is not None and row["status"] == "succeeded"


async def test_busy_worker_does_not_sleep_between_fast_jobs(
    producer: JobRepository, worker: JobRepository, automation_lab: Lab
) -> None:
    import time

    finished = 0
    ready = asyncio.Event()

    async def fast(context: ExecutionContext, payload: BaseModel) -> None:
        nonlocal finished
        finished += 1
        if finished >= 20:
            ready.set()

    registry = Registry()
    registry.register(JobDefinition("technical.slow", 1, Value, None, fast, max_runtime=30))
    worker.registry = registry
    for _ in range(20):
        await enqueue(producer, job_type="technical.slow")
    settings = WorkerSettings(
        service_name="cve-test-worker",
        app_env="test",
        database=automation_lab.settings("importer"),
        concurrency=2,
        batch_size=1,
        poll_seconds=1,
        lease_seconds=15,
        heartbeat_seconds=3,
    )
    runtime = Worker(worker, settings)
    stop = asyncio.Event()
    started = time.monotonic()
    task = asyncio.create_task(runtime.run(stop))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        assert time.monotonic() - started < 5
        assert len(runtime.active) <= 2
    finally:
        stop.set()
        await task


async def test_disconnected_database_and_socket_error_do_not_stop_worker(
    producer: JobRepository,
    worker: JobRepository,
    automation_lab: Lab,
) -> None:
    count = 0

    async def disconnected_once(context: ExecutionContext, payload: BaseModel) -> None:
        nonlocal count
        count += 1
        if count == 1:
            raise ConnectionResetError("Simulated upstream disconnect")

    registry = Registry()
    registry.register(
        JobDefinition("technical.retry", 1, Value, None, disconnected_once, max_runtime=3)
    )
    worker.registry = registry
    settings = WorkerSettings(
        service_name="cve-test-worker",
        app_env="test",
        database=automation_lab.settings("importer"),
        concurrency=1,
        poll_seconds=0.05,
        lease_seconds=1,
        heartbeat_seconds=0.1,
    )
    runtime = Worker(worker, settings)
    stop = asyncio.Event()
    loop = asyncio.create_task(runtime.run(stop))
    try:
        async with asyncio.timeout(10):
            while not runtime.healthy:
                await asyncio.sleep(0.05)
            with db.connect(automation_lab.config) as session:
                session.execute(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname='cve_monitoring' AND usename='importer'"
                )
            job = await enqueue(producer, job_type="technical.retry")
            while True:
                assert not loop.done()
                with db.connect(automation_lab.config) as session:
                    row = session.execute(
                        "SELECT status,attempts FROM automation.jobs WHERE id=%s", (job.id,)
                    ).fetchone()
                if row and row["status"] == "succeeded":
                    assert row["attempts"] == 2 and count == 2
                    break
                await asyncio.sleep(0.05)
            assert runtime.healthy
    finally:
        stop.set()
        await loop
