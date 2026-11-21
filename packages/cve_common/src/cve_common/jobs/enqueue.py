"""Enqueue joins the caller's explicit transaction; no hidden commit."""

from sqlalchemy.ext.asyncio import AsyncSession

from cve_common.jobs.contracts import JobEnvelope
from cve_common.jobs.models import Job
from cve_common.jobs.repository import JobRepository


async def enqueue(session: AsyncSession, repository: JobRepository, envelope: JobEnvelope) -> Job:
    return await repository.enqueue(session, envelope)
