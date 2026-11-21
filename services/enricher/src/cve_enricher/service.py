"""Existing fenced PostgreSQL workers, bounded backfill and separate EPSS publication."""

from typing import Any
from uuid import UUID

from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_common.jobs.errors import ErrorCode, JobError
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import JobDefinition, Registry
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_enricher.bulk import prepare, prepared_size
from cve_enricher.contracts import Configuration, EnrichmentError, Request, Result
from cve_enricher.epss import Client, activate, stream
from cve_enricher.normalize import canonical
from cve_enricher.pipeline import Pipeline
from cve_enricher.repository import enrich


class Service:
    def __init__(
        self,
        database: Database,
        cfg: Configuration,
        client: Client,
        pipeline: Pipeline | None = None,
    ) -> None:
        self.database, self.cfg, self.client = database, cfg, client
        self.pipeline = pipeline

    def registry(self) -> Registry:
        registry = Registry()
        for name in ["record", "backfill", "reconcile", "batch"]:
            registry.register(
                JobDefinition("cve.enrich." + name, 1, Request, Result, self.handle, 3600, 3)
            )
        if self.cfg.epss_enabled:
            registry.register(
                JobDefinition("cve.epss.sync_daily", 1, Request, Result, self.handle, 3600, 3)
            )
        return registry

    async def handle(self, context: ExecutionContext, payload: BaseModel) -> Result:
        request = Request.model_validate(payload.model_dump())
        if context.job.job_type == "cve.epss.sync_daily":
            return await self.epss(context, request)
        if context.job.job_type in {"cve.enrich.backfill", "cve.enrich.reconcile"}:
            return await self.backfill(context, request)
        if context.job.job_type == "cve.enrich.batch":
            if not self.pipeline or not request.identities:
                raise JobError(ErrorCode.INVALID_PAYLOAD)
            from cve_enricher.bulk import prepare_many

            values = await prepare_many(
                self.database,
                request.identities,
                context.job.id,
                context.job.correlation_id,
                self.cfg,
            )
            return await self.pipeline.submit(context, values, count=len(values))
        if not request.identity:
            raise JobError(ErrorCode.INVALID_PAYLOAD)

        if self.pipeline:
            value = await prepare(
                self.database,
                request.identity,
                context.job.id,
                context.job.correlation_id,
                self.cfg,
            )
            return await self.pipeline.submit(context, [value])

        async def commit(session: AsyncSession) -> Result:
            return await enrich(
                session,
                request.identity or "",
                context.job.id,
                context.job.correlation_id,
                self.cfg,
            )

        result = await context.complete(commit)
        assert isinstance(result, Result)
        return result

    async def backfill(self, context: ExecutionContext, request: Request) -> Result:
        if self.pipeline and request.record_id is not None:
            return await self.prepared_backfill(context, request)

        async def commit(session: AsyncSession) -> Result:
            if request.record_id is None:
                query = """SELECT identifier AS identity FROM cve.source_identifiers
WHERE identifier>:after AND NOT EXISTS(SELECT 1 FROM cve.v5_current_documents d
WHERE d.identity=identifier) ORDER BY identifier LIMIT :limit"""
            else:
                query = """SELECT identity FROM (
SELECT r.external_id AS identity FROM cve.source_records r
WHERE r.id=:record AND r.external_id<>'catalog'
UNION SELECT a.identifier FROM cve.source_revisions v
JOIN cve.source_record_identifiers a ON a.revision_id=v.id WHERE v.record_id=:record
) identities WHERE identity>:after ORDER BY identity LIMIT :limit"""
            values = (
                (
                    await session.execute(
                        text(query),
                        {
                            "after": request.after,
                            "limit": self.cfg.batch_size,
                            "record": request.record_id,
                        },
                    )
                )
                .scalars()
                .all()
            )
            if request.record_id is not None:
                # A source-specific reconcile already knows its bounded identities.
                # Resolve them in this fenced transaction instead of making a second job per CVE.
                for identity in values:
                    await enrich(
                        session, identity, context.job.id, context.job.correlation_id, self.cfg
                    )
            elif values:
                await session.execute(
                    text(
                        "SELECT "
                        "cve.enqueue_enrichment(value,:key||':'||value,:correl"
                        "ation) FROM jsonb_array_elements_text(CAST(:values "
                        "AS jsonb))"
                    ),
                    {
                        "key": str(context.job.id),
                        "correlation": context.job.correlation_id,
                        "values": canonical(list(values)),
                    },
                )
            if len(values) == self.cfg.batch_size:
                following = Request(
                    after=values[-1], record_id=request.record_id, event_id=request.event_id
                )
                await session.execute(
                    text(
                        "SELECT "
                        "automation.enqueue_job('cve.enrich.backfill',1,CAST(:payload AS "
                        "jsonb),:key,:correlation,0,NULL,NULL,3,'enrichment-backfill',fals"
                        "e)"
                    ),
                    {
                        "payload": following.model_dump_json(),
                        "key": str(context.job.id) + ":next",
                        "correlation": context.job.correlation_id,
                    },
                )
            return Result(count=len(values))

        result = await context.complete(commit)
        assert isinstance(result, Result)
        return result

    async def prepared_backfill(self, context: ExecutionContext, request: Request) -> Result:
        assert self.pipeline is not None
        async with transaction(self.database) as session:
            values = (
                (
                    await session.execute(
                        text("""
SELECT identity FROM (
SELECT r.external_id AS identity FROM cve.source_records r
WHERE r.id=:record AND r.external_id<>'catalog'
UNION SELECT a.identifier FROM cve.source_revisions v
JOIN cve.source_record_identifiers a ON a.revision_id=v.id WHERE v.record_id=:record
) identities WHERE identity>:after ORDER BY identity LIMIT :limit
"""),
                        {
                            "record": request.record_id,
                            "after": request.after,
                            "limit": self.cfg.batch_size,
                        },
                    )
                )
                .scalars()
                .all()
            )
        prepared = []
        for identity in values:
            prepared.append(
                await prepare(
                    self.database, identity, context.job.id, context.job.correlation_id, self.cfg
                )
            )
            prepared_size(prepared)

        async def following(session: AsyncSession) -> None:
            if len(values) == self.cfg.batch_size:
                payload = Request(
                    after=values[-1], record_id=request.record_id, event_id=request.event_id
                )
                await session.execute(
                    text("""
SELECT automation.enqueue_job('cve.enrich.backfill',1,CAST(:payload AS jsonb),:key,
:correlation,0,NULL,NULL,3,'enrichment-backfill',false)
"""),
                    {
                        "payload": payload.model_dump_json(),
                        "key": str(context.job.id) + ":next",
                        "correlation": context.job.correlation_id,
                    },
                )

        return await self.pipeline.submit(context, prepared, count=len(values), following=following)

    async def epss(self, context: ExecutionContext, request: Request) -> Result:
        assert self.database.engine is not None
        async with self.database.engine.connect() as lock:
            locked = (await lock.execute(text("SELECT pg_try_advisory_lock(160016)"))).scalar_one()
            await lock.commit()
            if not locked:
                raise JobError(ErrorCode.TEMPORARY)
            path = None
            dataset: UUID | None = None
            try:
                # Only this service owns scratch. Drop abandoned bounded gzip files on resume.
                self.client.scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
                for old in self.client.scratch.glob("*.csv.gz"):
                    if old.is_symlink():
                        raise EnrichmentError("epss_unsafe_scratch")
                    old.unlink()
                path, sha, url = await self.client.download(request.score_date)
                metadata: dict[str, Any] = {}
                sealed = False
                dataset = None
                async for page, done in stream(path, self.cfg, request.score_date):
                    if "model" in page:
                        metadata = page
                        async with context.atomic() as session:
                            dataset = (
                                await session.execute(
                                    text(
                                        "INSERT INTO "
                                        "cve.epss_import_runs(score_date,model_version,wire_sha25"
                                        "6,source_url) VALUES(CAST(:date AS "
                                        "date),:model,decode(:sha,'hex'),:url) ON "
                                        "CONFLICT(score_date,model_version,wire_sha256) DO "
                                        "UPDATE SET source_url=excluded.source_url WHERE "
                                        "cve.epss_import_runs.status<>'completed' RETURNING id"
                                    ),
                                    {**page, "sha": sha, "url": url},
                                )
                            ).scalar_one_or_none()
                            if dataset is None:
                                dataset = (
                                    await session.execute(
                                        text(
                                            "SELECT id FROM cve.epss_import_runs WHERE "
                                            "score_date=CAST(:date AS date) AND "
                                            "model_version=:model AND "
                                            "wire_sha256=decode(:sha,'hex')"
                                        ),
                                        {**page, "sha": sha},
                                    )
                                ).scalar_one()
                            sealed = (
                                await session.execute(
                                    text(
                                        "SELECT status='completed' FROM cve.epss_import_runs "
                                        "WHERE id=:id"
                                    ),
                                    {"id": dataset},
                                )
                            ).scalar_one()
                        continue
                    assert dataset is not None

                    async def write(
                        session: AsyncSession,
                        page: dict[str, Any] = page,
                        dataset: UUID = dataset,
                        sealed: bool = sealed,
                        metadata: dict[str, Any] = metadata,
                    ) -> Result:
                        if not sealed:
                            inserted = await session.execute(
                                text(
                                    "INSERT INTO "
                                    "cve.epss_daily_scores(dataset_id,cve_id,score_date,model_ver"
                                    "sion,score,percentile) SELECT :dataset,d.cve,CAST(:date AS "
                                    "date),:model,d.score::numeric,d.percentile::numeric FROM "
                                    "jsonb_to_recordset(CAST(:rows AS jsonb)) d(cve text,score "
                                    "text,percentile text) ON CONFLICT DO NOTHING RETURNING cve_id"
                                ),
                                {"dataset": dataset, **metadata, "rows": canonical(page["rows"])},
                            )
                            count_inserted = len(inserted.all())
                            await session.execute(
                                text(
                                    "UPDATE cve.epss_import_runs SET "
                                    "row_count=row_count+:count WHERE id=:id "
                                    "AND status<>'completed'"
                                ),
                                {"count": count_inserted, "id": dataset},
                            )
                        return (
                            await activate(
                                session,
                                dataset,
                                page["count"],
                                context.job.correlation_id,
                                self.cfg,
                            )
                            if "count" in page
                            else Result(dataset_id=dataset, count=len(page["rows"]))
                        )

                    if done:
                        result = await context.complete(write)
                        assert isinstance(result, Result)
                        return result
                    async with context.atomic() as session:
                        await write(session)
                raise EnrichmentError("epss_missing_end")
            except EnrichmentError:
                if dataset is not None:
                    async with context.atomic() as session:
                        await session.execute(
                            text(
                                "UPDATE cve.epss_import_runs SET "
                                "status='failed' WHERE id=:id AND "
                                "status<>'completed'"
                            ),
                            {"id": dataset},
                        )
                raise
            finally:
                if path:
                    path.unlink(missing_ok=True)
                await lock.execute(text("SELECT pg_advisory_unlock(160016)"))
                await lock.commit()
