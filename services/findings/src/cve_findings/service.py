"""Idempotent event receipts, bounded reconciliation and durable deadline maintenance."""

from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from cve_common.database.engine import Database
from cve_common.jobs.errors import ErrorCode, JobError
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import JobDefinition, Registry
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_findings.contracts import MatchingEvent, Request, Result
from cve_findings.repository import active_policy, apply, one, record, reprioritize, rows

PAGE = 100
ZERO = UUID(int=0)
KINDS = [
    "consume_matching_event",
    "reconcile",
    "refresh_priority",
    "check_deadlines",
    "check_exceptions",
    "backfill",
    "reevaluate",
    "maintenance",
]


async def enqueue(
    s: AsyncSession, kind: str, request: Request, correlation: UUID, key: str | None = None
) -> None:
    await s.execute(
        text(
            "SELECT automation.enqueue_job(:kind,1,CAST(:payload AS jsonb),:key,:correl"
            "ation,0,NULL,NULL,3,'findings',false)"
        ),
        {
            "kind": "findings." + kind,
            "payload": request.model_dump_json(),
            "key": key or str(uuid4()),
            "correlation": correlation,
        },
    )


class Service:
    def __init__(self, database: Database) -> None:
        self.database = database

    def registry(self) -> Registry:
        registry = Registry()
        for kind in KINDS:
            registry.register(
                JobDefinition("findings." + kind, 1, Request, Result, self.handle, 3600, 3)
            )
        return registry

    async def handle(self, context: ExecutionContext, payload: BaseModel) -> Result:
        request = Request.model_validate(payload.model_dump())
        kind = context.job.job_type.removeprefix("findings.")

        async def commit(s: AsyncSession) -> Result:
            if kind == "consume_matching_event":
                return await self.consume(s, context, request)
            if kind in {"reconcile", "backfill", "reevaluate"}:
                return await self.reconcile(s, context, request)
            if kind == "refresh_priority":
                return await self.refresh(s, context, request)
            if kind == "check_deadlines":
                return await self.deadlines(s, context, request)
            if kind == "check_exceptions":
                return await self.exceptions(s, context, request)
            for following in ["check_deadlines", "check_exceptions", "refresh_priority"]:
                await enqueue(
                    s,
                    following,
                    Request(),
                    context.job.correlation_id,
                    str(context.job.id) + ":" + following,
                )
            return Result(count=3)

        result = await context.complete(commit)
        assert isinstance(result, Result)
        return result

    async def consume(self, s: AsyncSession, ctx: ExecutionContext, req: Request) -> Result:
        if req.event_id is None:
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        await s.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key,18))"),
            {"key": "finding-event:" + str(req.event_id)},
        )
        receipt = await one(
            s, "SELECT finding_id FROM findings.event_receipts WHERE event_id=:id", id=req.event_id
        )
        if receipt:
            return Result(finding_id=receipt["finding_id"])
        event = await one(s, "SELECT * FROM automation.event_outbox WHERE id=:id", id=req.event_id)
        if (
            not event
            or event["source"] != "cve-matcher"
            or event["event_type"] not in {"matching.created", "matching.replaced"}
            or event["schema_version"] != 1
        ):
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        parsed = MatchingEvent.model_validate(event["payload"])
        match = await one(
            s, "SELECT * FROM matching.result_revisions WHERE id=:id", id=parsed.result_id
        )
        if (
            not match
            or any(
                match[column] != value
                for column, value in [
                    ("server_id", parsed.server_id),
                    ("snapshot_id", parsed.snapshot_id),
                    ("identity", parsed.identity),
                    ("enrichment_revision_id", parsed.enrichment_revision_id),
                    ("status", parsed.status),
                    ("rule_version", parsed.rule_version),
                ]
            )
            or event["aggregate_version"] != parsed.current_version
        ):
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        result, outcome = await apply(
            s, parsed.result_id, parsed.current_version, ctx.job.correlation_id
        )
        await s.execute(
            text(
                "INSERT INTO findings.event_receipts(event_id,job_id,result_id,finding_"
                "id,outcome) VALUES(:event,:job,:result,:finding,:outcome)"
            ),
            {
                "event": req.event_id,
                "job": ctx.job.id,
                "result": parsed.result_id,
                "finding": result.finding_id,
                "outcome": outcome,
            },
        )
        return result

    async def reconcile(self, s: AsyncSession, ctx: ExecutionContext, req: Request) -> Result:
        if req.result_id is not None and req.current_version is not None:
            return (await apply(s, req.result_id, req.current_version, ctx.job.correlation_id))[0]
        params: dict[str, Any] = {"after": req.after or ZERO, "limit": PAGE}
        if req.finding_id is not None:
            values = await rows(
                s,
                (
                    "SELECT c.result_id,c.current_version FROM findings.findings f JOIN mat"
                    "ching.current_results c ON c.server_id=f.server_id AND c.identity=f.cv"
                    "e_id WHERE f.id=:id AND f.model_version=2"
                ),
                id=req.finding_id,
            )
        else:
            # Keyset over result UUIDs; reconcile is explicit and never runs at startup.
            values = await rows(
                s,
                (
                    "SELECT c.result_id,c.current_version FROM matching.current_results c W"
                    "HERE c.result_id>:after ORDER BY c.result_id LIMIT :limit"
                ),
                **params,
            )
        for value in values:
            await enqueue(
                s,
                "reevaluate",
                Request(result_id=value["result_id"], current_version=value["current_version"]),
                ctx.job.correlation_id,
                str(ctx.job.id) + ":" + str(value["result_id"]),
            )
        if req.finding_id is None and len(values) == PAGE:
            await enqueue(
                s,
                "reconcile",
                Request(after=values[-1]["result_id"]),
                ctx.job.correlation_id,
                str(ctx.job.id) + ":next",
            )
        return Result(count=len(values))

    async def refresh(self, s: AsyncSession, ctx: ExecutionContext, req: Request) -> Result:
        values = await rows(
            s,
            (
                "SELECT id FROM findings.findings WHERE model_version=2 AND id>:after AND ("
                "CAST(:identity AS text) IS NULL OR cve_id=:identity) ORDER BY id LIMIT :li"
                "mit"
            ),
            after=req.after or ZERO,
            identity=req.identity,
            limit=PAGE,
        )
        changed = 0
        for value in values:
            finding = await one(
                s, "SELECT * FROM findings.findings WHERE id=:id FOR UPDATE", id=value["id"]
            )
            assert finding is not None
            changed += await reprioritize(s, finding, ctx.job.correlation_id)
        if len(values) == PAGE:
            await enqueue(
                s,
                "refresh_priority",
                Request(after=values[-1]["id"], identity=req.identity),
                ctx.job.correlation_id,
                str(ctx.job.id) + ":next",
            )
        return Result(count=changed)

    async def deadlines(self, s: AsyncSession, ctx: ExecutionContext, req: Request) -> Result:
        _, policy = await active_policy(s)
        warning = policy.deadline_warning_hours or 0
        values = await rows(
            s,
            (
                "SELECT f.id FROM findings.findings f JOIN findings.deadlines d ON d.id=f.c"
                "urrent_deadline_id WHERE f.model_version=2 AND f.status IN ('open','in_pro"
                "gress') AND f.id>:after AND d.due_at<=clock_timestamp()+make_interval(hour"
                "s=>:warning) ORDER BY f.id LIMIT :limit"
            ),
            after=req.after or ZERO,
            warning=warning,
            limit=PAGE,
        )
        count = 0
        for value in values:
            f = await one(
                s,
                (
                    "SELECT f.*,d.due_at FROM findings.findings f JOIN findings.deadlines d"
                    " ON d.id=f.current_deadline_id WHERE f.id=:id FOR UPDATE OF f"
                ),
                id=value["id"],
            )
            if f is None or f["status"] not in {"open", "in_progress"}:
                continue
            now = (await s.execute(text("SELECT clock_timestamp()"))).scalar_one()
            if f["due_at"] > now + timedelta(hours=warning):
                continue
            kind = "overdue" if f["due_at"] < now else "approaching"
            if kind == "approaching" and not policy.deadline_warning_hours:
                continue
            inserted = (
                await s.execute(
                    text(
                        "INSERT INTO findings.escalations(deadline_id,kind) VALUES(:dea"
                        "dline,:kind) ON CONFLICT DO NOTHING RETURNING deadline_id"
                    ),
                    {"deadline": f["current_deadline_id"], "kind": kind},
                )
            ).first()
            if inserted:
                await s.execute(
                    text("UPDATE findings.findings SET version=version+1 WHERE id=:id"),
                    {"id": f["id"]},
                )
                await record(
                    s,
                    f["id"],
                    "overdue" if kind == "overdue" else "deadline_approaching",
                    f,
                    "approved_deadline_stage",
                    ctx.job.correlation_id,
                )
                count += 1
        if len(values) == PAGE:
            await enqueue(
                s,
                "check_deadlines",
                Request(after=values[-1]["id"]),
                ctx.job.correlation_id,
                str(ctx.job.id) + ":next",
            )
        return Result(count=count)

    async def exceptions(self, s: AsyncSession, ctx: ExecutionContext, req: Request) -> Result:
        values = await rows(
            s,
            (
                "SELECT e.id,e.finding_id FROM findings.exception_state e WHERE e.id>:after"
                " AND e.decision='approved' AND e.valid_until<=clock_timestamp() ORDER BY e"
                ".id LIMIT :limit"
            ),
            after=req.after or ZERO,
            limit=PAGE,
        )
        count = 0
        for value in values:
            f = await one(
                s, "SELECT * FROM findings.findings WHERE id=:id FOR UPDATE", id=value["finding_id"]
            )
            assert f is not None
            e = await one(s, "SELECT * FROM findings.exception_state WHERE id=:id", id=value["id"])
            if not e or e["decision"] != "approved":
                continue
            await s.execute(
                text(
                    "INSERT INTO findings.exception_decisions(exception_id,number,decis"
                    "ion,reason) VALUES(:id,:number,'expired','validity_period_ended')"
                ),
                {"id": e["id"], "number": e["decision_version"] + 1},
            )
            await s.execute(
                text("UPDATE findings.findings SET version=version+1 WHERE id=:id"), {"id": f["id"]}
            )
            await record(
                s,
                f["id"],
                "exception_expired",
                f,
                "exception_validity_ended",
                ctx.job.correlation_id,
            )
            count += 1
        if len(values) == PAGE:
            await enqueue(
                s,
                "check_exceptions",
                Request(after=values[-1]["id"]),
                ctx.job.correlation_id,
                str(ctx.job.id) + ":next",
            )
        return Result(count=count)
