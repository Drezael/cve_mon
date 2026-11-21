"""Claim only free execution capacity; every reservation is committed before execution."""

from uuid import UUID

from cve_common.jobs.models import Job
from cve_common.jobs.repository import JobRepository


async def claim(repository: JobRepository, worker: UUID, lease: float) -> Job | None:
    return await repository.claim(worker, lease)
