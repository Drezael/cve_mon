"""Fenced batches and safe source checkpoints using the existing persistent worker engine."""

import asyncio
import hashlib
import os
import shutil
import stat
import time
from pathlib import Path
from typing import Any, cast

from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_common.jobs.errors import ErrorCode, JobError, LeaseLost
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import JobDefinition, Registry
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_importer.adapters import Adapters, Page
from cve_importer.contracts import SOURCES, Configuration, ImportFailure, Request, Result, Source
from cve_importer.repository import Event, events, finish, persist
from cve_importer.transport import Transport
from cve_importer.validation import canonical


class Service:
    def __init__(
        self, database: Database, configuration: Configuration, transport: Transport
    ) -> None:
        self.database, self.configuration, self.transport = database, configuration, transport

    async def reserve(self, source: str, seconds: float) -> float:
        async with transaction(self.database) as session:
            return float(
                (
                    await session.execute(
                        text("SELECT cve.reserve_request(:source,:delay)"),
                        {"source": source, "delay": seconds},
                    )
                ).scalar_one()
            )

    def registry(self) -> Registry:
        result = Registry()
        for source in SOURCES:
            result.register(
                JobDefinition(
                    "cve.import." + source,
                    1,
                    Request,
                    Result,
                    self.handle,
                    max_runtime=3600,
                    max_attempts=3,
                )
            )
        return result

    async def lock(self, session: AsyncSession, run: dict[str, Any]) -> None:
        owner = (
            await session.execute(
                text("SELECT active_run FROM cve.source_leases WHERE source_id=:source FOR UPDATE"),
                {"source": run["source_id"]},
            )
        ).scalar_one()
        if owner != run["id"]:
            raise LeaseLost()

    async def handle(self, context: ExecutionContext, payload: BaseModel) -> Result:
        request = Request.model_validate(payload.model_dump())
        async with transaction(self.database) as session:
            row = (
                (
                    await session.execute(
                        text("SELECT * FROM cve.import_runs WHERE id=:id"), {"id": request.run_id}
                    )
                )
                .mappings()
                .one()
            )
            run = dict(row)
            cursors: dict[str, Any] = dict(
                (
                    await session.execute(
                        text(
                            "SELECT stream,cursor FROM cve.source_streams WHERE source_id=:source"
                        ),
                        {"source": run["source_id"]},
                    )
                ).all()
            )
            if (
                run["source_id"] == "cve_list"
                and run["context"].get("configuration", {}).get("cve_list_transport", "git")
                == "git"
            ):
                previous = (
                    (
                        await session.execute(
                            text("""
SELECT id,status,progress FROM cve.import_runs WHERE source_id='cve_list'
AND status IN ('completed','partial') AND progress->'git'->>'head' IS NOT NULL
AND progress->'git'->>'offset'=progress->'git'->>'count'
ORDER BY finished_at DESC,id DESC LIMIT 1
""")
                        )
                    )
                    .mappings()
                    .first()
                )
                if previous and previous["status"] == "partial":
                    failed = (
                        (
                            await session.execute(
                                text(
                                    "SELECT position FROM cve.import_errors "
                                    "WHERE run_id=:run ORDER BY position"
                                ),
                                {"run": previous["id"]},
                            )
                        )
                        .scalars()
                        .all()
                    )
                    cursors["main"] = {
                        "git_commit": previous["progress"]["git"]["head"],
                        "git_retry_paths": [p.split(":", 1)[-1] for p in failed],
                    }
        if (
            context.job.job_type != "cve.import." + run["source_id"]
            or run["source_id"] not in self.configuration.enabled
        ):
            raise JobError(ErrorCode.FORBIDDEN)
        cfg = Configuration.model_validate(run["context"].get("configuration", {}))
        if not set(cfg.osv_ecosystems) <= set(self.configuration.osv_ecosystems):
            raise JobError(ErrorCode.FORBIDDEN)
        async with context.atomic() as session:
            await self.lock(session, run)
            await session.execute(
                text(
                    "UPDATE cve.import_runs SET "
                    "status='running',job_id=:job,started_at=COALESCE(started_at,clock"
                    "_timestamp()),finished_at=NULL WHERE id=:id AND status NOT IN "
                    "('completed','partial')"
                ),
                {"id": run["id"], "job": context.job.id},
            )
        adapter = Adapters(
            cast(Source, run["source_id"]),
            run["id"],
            run["mode"],
            cfg,
            self.transport,
            cursors,
            run["created_at"],
        )
        progress = run["progress"]
        try:
            while True:
                page = await adapter.next(progress)
                origin = hashlib.sha256(page.artifact.location.encode()).hexdigest()[:16]
                page.errors = [
                    {**e, "position": origin + ":" + e["position"][:480]} for e in page.errors
                ]
                for item in page.records:
                    self.transport.secret_check(canonical(item["original_json"]))

                async def operation(
                    session: AsyncSession, page: Page = page, progress: dict[str, Any] = progress
                ) -> Result | None:
                    await self.lock(session, run)
                    latest = (
                        await session.execute(
                            text("SELECT progress FROM cve.import_runs WHERE id=:id FOR UPDATE"),
                            {"id": run["id"]},
                        )
                    ).scalar_one()
                    if latest != progress:
                        raise LeaseLost()
                    started = time.monotonic()
                    await persist(session, run, page)
                    await session.execute(
                        text(
                            "UPDATE cve.import_runs SET progress=CAST(:progress AS "
                            "jsonb),write_ms=write_ms+:elapsed WHERE id=:id"
                        ),
                        {
                            "id": run["id"],
                            "progress": canonical(page.progress),
                            "elapsed": (time.monotonic() - started) * 1000,
                        },
                    )
                    if page.done:
                        status = await finish(session, run, page, cfg.kev_minimum_fraction)
                        return Result.model_validate({"run_id": run["id"], "status": status})
                    return None

                if page.done:
                    result = await context.complete(operation)
                    assert isinstance(result, Result)
                    if result.status == "completed":
                        directory = self.transport.directory(run["id"])
                        shutil.rmtree(directory)
                    return result
                async with context.atomic() as session:
                    await operation(session)
                progress = page.progress
                if context.stopping.is_set():
                    raise asyncio.CancelledError()
        except ImportFailure as error:
            code = str(error)

            async def reject(session: AsyncSession) -> Result:
                await self.lock(session, run)
                await session.execute(
                    text(
                        "INSERT INTO cve.import_errors(run_id,position,code) "
                        "VALUES(:run,'run',:code) ON CONFLICT DO NOTHING"
                    ),
                    {"run": run["id"], "code": code},
                )
                await session.execute(
                    text(
                        "UPDATE cve.import_runs SET "
                        "status='partial',error_count=error_count+1,finished_at=clock_time"
                        "stamp() WHERE id=:run"
                    ),
                    {"run": run["id"]},
                )
                await session.execute(
                    text(
                        "UPDATE cve.source_leases SET active_run=NULL WHERE "
                        "source_id=:source AND active_run=:run"
                    ),
                    {"source": run["source_id"], "run": run["id"]},
                )
                await events(
                    session,
                    run,
                    [("partial", Event(run_id=run["id"], source_id=run["source_id"], code=code))],
                )
                await session.execute(
                    text(
                        "INSERT INTO system.source_sync_state(source_id,last_error_code) "
                        "VALUES(:source,:code) ON CONFLICT(source_id) DO UPDATE SET "
                        "last_error_code=excluded.last_error_code,updated_at=clock_timestamp()"
                    ),
                    {"source": run["source_id"], "code": code},
                )
                await session.execute(
                    text(
                        "INSERT INTO "
                        "security.audit_log(action,object_type,object_id,request_id,outcom"
                        "e,metadata) "
                        "VALUES('cve.source.partial','cve_import',:id,:cid,'denied',jsonb_"
                        "build_object('code',CAST(:code AS text)))"
                    ),
                    {"id": str(run["id"]), "cid": run["correlation_id"], "code": code},
                )
                return Result(run_id=run["id"], status="partial")

            result = await context.complete(reject)
            assert isinstance(result, Result)
            return result
        finally:
            await adapter.close()


def proof(path: Path) -> bool:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                return False
            value = handle.read(512).strip()
        return value == os.readlink("/proc/self/ns/net")
    except (OSError, UnicodeError):
        return False
