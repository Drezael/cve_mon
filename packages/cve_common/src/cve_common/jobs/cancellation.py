"""Explicit administrative operations; database validates the caller, never a header."""

from uuid import UUID

from cve_common.jobs.repository import JobRepository


async def cancel(repository: JobRepository, job_id: UUID) -> UUID:
    return await repository.control(job_id, "cancel")


async def replay(repository: JobRepository, job_id: UUID) -> UUID:
    return await repository.control(job_id, "replay")
