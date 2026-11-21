"""Fenced transaction helpers: stale handlers cannot commit guarded database effects."""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_common.database.transactions import transaction
from cve_common.jobs.errors import LeaseLost
from cve_common.jobs.models import Job
from cve_common.jobs.registry import JobDefinition
from cve_common.jobs.repository import JobRepository


class ExecutionContext:
    def __init__(
        self,
        repository: JobRepository,
        job: Job,
        definition: JobDefinition,
        stopping: asyncio.Event,
    ) -> None:
        self.repository = repository
        self.job = job
        self.definition = definition
        self.stopping = stopping
        self.completed = False
        self.completing = False

    def validate_result(self, result: BaseModel | None) -> BaseModel | None:
        if self.definition.result_type is None:
            if result is not None:
                raise ValueError("Unexpected job result")
            return None
        if result is None:
            raise ValueError("Missing job result")
        return self.definition.result_type.model_validate(result.model_dump())

    @asynccontextmanager
    async def atomic(self) -> AsyncIterator[AsyncSession]:
        async with transaction(self.repository.database) as session:
            yield session
            valid = (
                await session.execute(
                    text("SELECT automation.check_job_fence(:id,:worker,:token,:epoch)"),
                    self.repository.fence(self.job),
                )
            ).scalar_one()
            if not valid:
                raise LeaseLost()

    async def complete(
        self, operation: Callable[[AsyncSession], Awaitable[BaseModel | None]]
    ) -> BaseModel | None:
        """Database effect + outbox + success in one transaction, with validated result."""
        if self.completed:
            raise RuntimeError("Job already completed")
        self.completing = True
        try:
            async with transaction(self.repository.database) as session:
                result = self.validate_result(await operation(session))
                if not await self.repository.finish_in(session, self.job, "succeeded"):
                    raise LeaseLost()
            self.completed = True
            return result
        finally:
            self.completing = False
