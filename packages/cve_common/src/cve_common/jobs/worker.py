"""Bounded worker loop, short claims, independent heartbeat sessions and graceful drain."""

import asyncio
import contextlib
import logging
import time
from uuid import UUID, uuid4

from pydantic import Field, model_validator
from sqlalchemy.exc import SQLAlchemyError

from cve_common.config.settings import DatabaseSettings, ServiceSettings
from cve_common.jobs.errors import ErrorCode, JobError, LeaseLost, classify
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.models import Job
from cve_common.jobs.repository import JobRepository
from cve_common.logging.correlation import correlation_id, request_id


class WorkerSettings(ServiceSettings):
    database: DatabaseSettings
    concurrency: int = Field(default=2, ge=1, le=8)
    batch_size: int = Field(default=2, ge=1, le=8)
    lease_seconds: float = Field(default=15, ge=0.2, le=300)
    heartbeat_seconds: float = Field(default=3, ge=0.05, le=100)
    poll_seconds: float = Field(default=0.5, ge=0.05, le=10)
    shutdown_seconds: float = Field(default=5, ge=0.1, le=30)
    paused: bool = False

    @model_validator(mode="after")
    def bounded_resources(self) -> "WorkerSettings":
        if (
            self.heartbeat_seconds > self.lease_seconds / 3
            or self.concurrency >= self.database.pool_size
        ):
            raise ValueError("Heartbeat and worker concurrency require pool headroom")
        return self


class Worker:
    def __init__(
        self, repository: JobRepository, settings: WorkerSettings, *, worker_id: UUID | None = None
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.id = worker_id or uuid4()
        self.last_tick = 0.0
        self.healthy = False
        self.active: set[asyncio.Task[None]] = set()
        self.wake = asyncio.Event()
        self.log = logging.getLogger("cve.jobs")

    async def _heartbeat(
        self, job: Job, task: asyncio.Task[None], context: ExecutionContext
    ) -> None:
        try:
            while True:
                await asyncio.sleep(self.settings.heartbeat_seconds)
                if context.completed:
                    return
                if not await self.repository.heartbeat(job, self.settings.lease_seconds):
                    # Atomic completion clears the lease before the handler releases
                    # its files and parser processes. That is not a lost lease.
                    # The completing transaction still checks its own fencing token.
                    if not context.completed and not context.completing:
                        task.cancel()
                    return
        except (SQLAlchemyError, OSError, TimeoutError):
            self.healthy = False
            if not context.completed and not context.completing:
                task.cancel()

    async def execute(self, job: Job, stop: asyncio.Event) -> None:
        request_token = request_id.set(None)
        token = correlation_id.set(str(job.correlation_id))
        current = asyncio.current_task()
        assert current is not None
        heartbeat = None
        try:
            definition = self.repository.registry.get(job.job_type, job.payload_version)
            context = ExecutionContext(self.repository, job, definition, stop)
            payload = definition.payload_type.model_validate(job.payload)
            heartbeat = asyncio.create_task(self._heartbeat(job, current, context))
            async with asyncio.timeout(
                min(definition.max_runtime, max(0.001, job.remaining_seconds))
            ):
                result = await definition.handler(context, payload)
                context.validate_result(result)
            if not context.completed and not await self.repository.finish(job, "succeeded"):
                raise LeaseLost()
            self.log.info("job_finished", extra={"job_id": str(job.id), "worker_id": str(self.id)})
        except asyncio.CancelledError:
            try:
                await self.repository.finish(job, "retry", ErrorCode.SHUTDOWN)
            except (SQLAlchemyError, OSError, TimeoutError):
                self.healthy = False
        except Exception as error:
            failure = classify(error)
            diagnostic = (
                error.diagnostic_code if isinstance(error, JobError) else None
            ) or failure.code.value
            error_class = type(error).__name__[:64]
            self.log.warning(
                "job_failed",
                extra={
                    "job_id": str(job.id),
                    "error_code": failure.code.value,
                    "diagnostic_code": diagnostic,
                    "error_class": error_class,
                },
            )
            if not isinstance(error, LeaseLost):
                try:
                    await self.repository.finish(
                        job,
                        "retry" if failure.retry else "failed",
                        failure.code,
                        diagnostic_code=diagnostic,
                        error_class=error_class,
                    )
                except (SQLAlchemyError, OSError, TimeoutError):
                    self.healthy = False
        finally:
            if heartbeat is not None:
                heartbeat.cancel()
                await asyncio.gather(heartbeat, return_exceptions=True)
            correlation_id.reset(token)
            request_id.reset(request_token)

    def completed(self, task: asyncio.Task[None]) -> None:
        self.active.discard(task)
        self.wake.set()

    async def run(self, stop: asyncio.Event) -> None:
        async def wake_on_stop() -> None:
            await stop.wait()
            self.wake.set()

        stopper = asyncio.create_task(wake_on_stop())
        next_recovery = 0.0
        recovery_requested = False
        try:
            while not stop.is_set():
                self.wake.clear()
                self.last_tick = time.monotonic()
                claimed = False
                try:
                    if not recovery_requested:
                        await self.repository.request_recovery(self.id)
                        recovery_requested = True
                    if self.last_tick >= next_recovery:
                        recovered = await self.repository.recover()
                        if recovered:
                            await self.repository.request_recovery(uuid4())
                        next_recovery = self.last_tick + self.settings.poll_seconds
                    self.healthy = True
                    free = min(
                        self.settings.batch_size, self.settings.concurrency - len(self.active)
                    )
                    for _ in range(0 if self.settings.paused else free):
                        if stop.is_set():
                            break
                        job = await self.repository.claim(self.id, self.settings.lease_seconds)
                        if job is None:
                            break
                        if stop.is_set():
                            await self.repository.finish(job, "retry", ErrorCode.SHUTDOWN)
                            break
                        claimed = True
                        task = asyncio.create_task(self.execute(job, stop))
                        self.active.add(task)
                        task.add_done_callback(self.completed)
                except (SQLAlchemyError, OSError, TimeoutError):
                    self.healthy = False
                    self.log.warning("worker_unavailable")
                # Polling backs off an idle queue; completed work immediately frees a slot.
                if claimed and len(self.active) < self.settings.concurrency:
                    continue
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self.wake.wait(), self.settings.poll_seconds)
        finally:
            stopper.cancel()
            await asyncio.gather(stopper, return_exceptions=True)
            if self.active:
                _, pending = await asyncio.wait(self.active, timeout=self.settings.shutdown_seconds)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            self.healthy = False
