"""Atomic creation/claims, real locks, fencing, retries and guarded business effects."""

import asyncio
from uuid import uuid4

import psycopg
import pytest
from cve_common.database.transactions import transaction
from cve_common.jobs.contracts import JobEnvelope
from cve_common.jobs.errors import IdempotencyConflict
from cve_common.jobs.models import Job
from cve_common.jobs.repository import JobRepository
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from scripts.database import manage as db
from tests.automation.integration.conftest import Lab

pytestmark = [pytest.mark.automation, pytest.mark.security]


def envelope(**extra: object) -> JobEnvelope:
    return JobEnvelope.model_validate(
        {
            "job_type": "technical.success",
            "payload": {"value": 1},
            "idempotency_key": uuid4().hex,
            **extra,
        }
    )


async def enqueue(repository: JobRepository, **extra: object) -> Job:
    async with transaction(repository.database) as session:
        return await repository.enqueue(session, envelope(**extra))


async def test_concurrent_idempotency(producer: JobRepository) -> None:
    job = envelope()

    async def submit() -> Job:
        async with transaction(producer.database) as session:
            return await producer.enqueue(session, job)

    results = await asyncio.gather(*(submit() for _ in range(8)))
    assert len({j.id for j in results}) == 1
    with pytest.raises(IdempotencyConflict):
        async with transaction(producer.database) as session:
            await producer.enqueue(session, job.model_copy(update={"payload": {"value": 2}}))


async def test_claim_finish_and_no_late_success(
    producer: JobRepository, worker: JobRepository
) -> None:
    job = await enqueue(producer)
    claimed = await worker.claim(uuid4(), 1)
    assert claimed is not None
    # Earlier tests may leave other queued records; complete only the returned lease.
    assert await worker.heartbeat(claimed, 1)
    assert not await worker.heartbeat(claimed.model_copy(update={"lease_token": uuid4()}), 1)
    assert await worker.finish(claimed, "succeeded")
    assert not await worker.finish(claimed, "succeeded")
    assert job.status == "queued"


async def test_many_claimers_get_distinct_jobs(
    producer: JobRepository, worker: JobRepository
) -> None:
    for _ in range(16):
        await enqueue(producer)
    claims = await asyncio.gather(*(worker.claim(uuid4(), 2) for _ in range(12)))
    nonempty = [j for j in claims if j is not None]
    assert len(nonempty) == 12 and len({j.id for j in nonempty}) == 12
    for job in nonempty:
        assert await worker.finish(job, "succeeded")


async def test_expired_owner_fenced_and_attempt_preserved(
    producer: JobRepository, worker: JobRepository, automation_lab: Lab
) -> None:
    await enqueue(producer)
    old = await worker.claim(uuid4(), 0.2)
    assert old is not None
    await asyncio.sleep(0.25)
    assert not await worker.heartbeat(old, 1)
    assert not await worker.finish(old, "succeeded")
    await worker.recover()
    await asyncio.sleep(0.25)
    newer = None
    for _ in range(25):
        candidate = await worker.claim(uuid4(), 2)
        if candidate is None:
            break
        if candidate.id == old.id:
            newer = candidate
            break
        await worker.finish(candidate, "succeeded")
    assert newer is not None and newer.fencing_token > old.fencing_token
    assert not await worker.finish(old, "succeeded")
    assert await worker.finish(newer, "succeeded")
    with db.connect(automation_lab.config, "cve_migrator") as connection:
        connection.execute("SET ROLE postgres_owner")
        rows = connection.execute(
            "SELECT outcome FROM automation.job_attempts WHERE job_id=%s ORDER BY attempt",
            (old.id,),
        ).fetchall()
        assert [r["outcome"] for r in rows] == ["lease_lost", "succeeded"]


async def test_managed_rows_cannot_be_updated_directly(
    producer: JobRepository, worker: JobRepository, automation_lab: Lab
) -> None:
    # A runtime role cannot activate legacy data by bypassing the enqueue function.
    with (
        db.connect(automation_lab.config, "api_ingest") as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(
            "UPDATE automation.jobs SET runtime_version=1,creator_role=current_user,"
            "correlation_id=gen_random_uuid(),request_fingerprint=sha256('x'::bytea) "
            "WHERE idempotency_key='legacy-preserved'"
        )
    job = await enqueue(producer)
    with pytest.raises(DBAPIError):
        async with transaction(worker.database) as session:
            await session.execute(
                text("UPDATE automation.jobs SET status='succeeded' WHERE id=:id"), {"id": job.id}
            )
    with pytest.raises(DBAPIError):
        async with transaction(producer.database) as session:
            await session.execute(
                text("SELECT * FROM automation.claim_job(ARRAY['technical.success'],:worker,1)"),
                {"worker": uuid4()},
            )


async def test_cancel_release_and_replay(producer: JobRepository, worker: JobRepository) -> None:
    job = await enqueue(producer, pending=True)
    await producer.control(job.id, "release")
    await producer.control(job.id, "cancel")
    replayed = await producer.control(job.id, "replay")
    assert replayed != job.id
    with pytest.raises(DBAPIError):
        await worker.control(replayed, "cancel")
