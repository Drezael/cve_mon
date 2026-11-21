"""A completed job must finish releasing its Git cache before the heartbeat stops."""

import asyncio
import fcntl
import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

from cve_common.config.settings import DatabaseSettings
from cve_common.jobs.contracts import Payload as StrictPayload
from cve_common.jobs.models import Job
from cve_common.jobs.registry import JobDefinition, Registry
from cve_common.jobs.worker import Worker, WorkerSettings
from cve_importer.contracts import Configuration
from cve_importer.git_source import GitSource
from pydantic import BaseModel


async def test_completed_job_cleanup_is_not_cancelled_by_its_own_heartbeat(tmp_path: Path) -> None:
    class Payload(StrictPayload):
        pass

    class SlowPool:
        def shutdown(self, **kwargs: Any) -> None:
            time.sleep(0.2)

    path = tmp_path / "repository.lock"
    source = GitSource(SimpleNamespace(scratch=tmp_path), uuid4(), Configuration())  # type: ignore[arg-type]
    source.lock = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(source.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    source.pool = SlowPool()  # type: ignore[assignment]
    cleaned = False
    terminal = False

    async def handler(context: Any, payload: BaseModel) -> None:
        nonlocal terminal, cleaned
        # ExecutionContext.complete has durably marked the job succeeded.
        terminal = context.completed = True
        await source.close()
        cleaned = True

    class Repository:
        def __init__(self) -> None:
            self.database = None
            self.registry = Registry()
            self.registry.register(JobDefinition("cleanup.test", 1, Payload, None, handler, 2))

        async def heartbeat(self, *args: Any) -> bool:
            return not terminal

        async def finish(self, *args: Any, **kwargs: Any) -> bool:
            return False

    settings = WorkerSettings(
        service_name="cve-test",
        app_env="test",
        database=DatabaseSettings.model_validate(
            {
                "host": "cve-postgres",
                "username": "importer",
                "password_file": tmp_path / "secret",
                "ca_file": tmp_path / "ca",
                "pool_size": 5,
            }
        ),
        concurrency=1,
        heartbeat_seconds=0.05,
        lease_seconds=0.3,
    )
    job = Job.model_validate(
        {
            "id": uuid4(),
            "correlation_id": uuid4(),
            "job_type": "cleanup.test",
            "payload_version": 1,
            "payload": {},
            "remaining_seconds": 2,
            "status": "running",
            "attempts": 1,
            "max_attempts": 3,
            "fencing_token": 1,
        }
    )
    runtime = Worker(Repository(), settings)  # type: ignore[arg-type]
    try:
        await runtime.execute(job, asyncio.Event())
        assert cleaned, "Heartbeat cancelled the completed handler while it released the Git lock"
        assert source.lock is None
        fd = os.open(path, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
    finally:
        if source.lock is not None:
            os.close(source.lock)
            source.lock = None


async def test_cancelled_parser_cleanup_reaps_before_releasing_cache(tmp_path: Path) -> None:
    import pytest

    closed = False

    class Pool:
        def shutdown(self, **kwargs: Any) -> None:
            nonlocal closed
            time.sleep(0.2)
            closed = True

    source = GitSource(SimpleNamespace(scratch=tmp_path), uuid4(), Configuration())  # type: ignore[arg-type]
    source.lock = os.open(tmp_path / "cache.lock", os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(source.lock, fcntl.LOCK_EX)
    source.pool = Pool()  # type: ignore[assignment]
    cleanup = asyncio.create_task(source.close())
    await asyncio.sleep(0.03)
    cleanup.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cleanup
    assert closed and source.lock is None
