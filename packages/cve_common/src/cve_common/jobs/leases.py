"""Lease operations are checked against PostgreSQL clock, owner, random token and epoch."""

from cve_common.jobs.models import Job
from cve_common.jobs.repository import JobRepository


async def heartbeat(repository: JobRepository, job: Job, lease: float) -> bool:
    return await repository.heartbeat(job, lease)
