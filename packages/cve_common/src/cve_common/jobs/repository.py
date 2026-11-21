"""Short transactions invoke guarded PostgreSQL operations; never commit an external effect."""

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_common.jobs.contracts import JobEnvelope
from cve_common.jobs.errors import ErrorCode, IdempotencyConflict
from cve_common.jobs.models import Job
from cve_common.jobs.registry import Registry


class JobRepository:
    def __init__(self, database: Database, registry: Registry) -> None:
        self.database = database
        self.registry = registry

    async def enqueue(self, session: AsyncSession, envelope: JobEnvelope) -> Job:
        definition = self.registry.get(envelope.job_type, envelope.payload_version)
        definition.payload_type.model_validate(envelope.payload)
        if envelope.max_attempts > definition.max_attempts:
            raise ValueError("Retry contract exceeded")
        params = envelope.model_dump(exclude={"payload"})
        params["payload"] = json.dumps(envelope.payload, allow_nan=False)
        sql = (
            "SELECT * FROM automation.enqueue_job(:job_type,:payload_version,"
            "CAST(:payload AS jsonb),:idempotency_key,:correlation_id,:priority,"
            ":scheduled_at,:deadline,:max_attempts,:scope,:pending)"
        )
        try:
            row = (await session.execute(text(sql), params)).mappings().one()
        except IntegrityError as error:
            if getattr(error.orig, "sqlstate", None) == "23505":
                raise IdempotencyConflict("Idempotency conflict") from None
            raise
        return Job.model_validate(dict(row))

    async def claim(self, worker: UUID, lease: float) -> Job | None:
        if not self.registry.names:
            return None
        async with transaction(self.database) as session:
            row = (
                (
                    await session.execute(
                        text(
                            "SELECT j.*,extract(epoch FROM j.execution_deadline-clock_timestam"
                            "p()) AS remaining_seconds FROM automation.claim_job(:types,:worke"
                            "r,:lease) j"
                        ),
                        {"types": self.registry.names, "worker": worker, "lease": lease},
                    )
                )
                .mappings()
                .first()
            )
            return Job.model_validate(dict(row)) if row else None

    async def heartbeat(self, job: Job, lease: float) -> bool:
        async with transaction(self.database) as session:
            return bool(
                (
                    await session.execute(
                        text("SELECT automation.heartbeat_job(:id,:worker,:token,:epoch,:lease)"),
                        {**self.fence(job), "lease": lease},
                    )
                ).scalar_one()
            )

    @staticmethod
    def fence(job: Job) -> dict[str, Any]:
        return {
            "id": job.id,
            "worker": job.lease_owner,
            "token": job.lease_token,
            "epoch": job.fencing_token,
        }

    async def finish_in(
        self,
        session: AsyncSession,
        job: Job,
        outcome: str,
        error: ErrorCode | None = None,
        result: UUID | None = None,
    ) -> bool:
        return bool(
            (
                await session.execute(
                    text(
                        "SELECT automation.finish_job(:id,:worker,:token,:epoch,:outcome,:"
                        "error,:result)"
                    ),
                    {
                        **self.fence(job),
                        "outcome": outcome,
                        "error": error.value if error else None,
                        "result": result,
                    },
                )
            ).scalar_one()
        )

    async def finish(
        self,
        job: Job,
        outcome: str,
        error: ErrorCode | None = None,
        *,
        diagnostic_code: str | None = None,
        error_class: str | None = None,
    ) -> bool:
        async with transaction(self.database) as session:
            if diagnostic_code and error_class:
                await session.execute(
                    text("SELECT automation.diagnose_job(:id,:worker,:token,:epoch,:code,:class)"),
                    {**self.fence(job), "code": diagnostic_code, "class": error_class},
                )
            return await self.finish_in(session, job, outcome, error)

    async def request_recovery(self, identity: UUID) -> None:
        if not self.registry.names:
            return
        async with transaction(self.database) as session:
            await session.execute(
                text("SELECT automation.request_worker_recovery(:id,:types)"),
                {"id": identity, "types": self.registry.names},
            )

    async def recover(self) -> int:
        async with transaction(self.database) as session:
            return int(
                (await session.execute(text("SELECT automation.recover_jobs()"))).scalar_one()
            )

    async def control(self, job_id: UUID, action: str) -> UUID:
        if action not in {"release", "cancel", "replay"}:
            raise ValueError("Unknown control action")
        async with transaction(self.database) as session:
            return UUID(
                str(
                    (
                        await session.execute(
                            text("SELECT automation.control_job(:id,:action)"),
                            {"id": job_id, "action": action},
                        )
                    ).scalar_one()
                )
            )
