"""Durable decisions from trusted Finding events and recoverable n8n orchestration."""

import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

from cve_common.database.engine import Database
from cve_common.jobs.errors import ErrorCode, JobError
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import JobDefinition, Registry
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_notification.contracts import EVENTS, Request, Result, Rule
from cve_notification.repository import change, enqueue, one, rows

PAGE = 100


class Service:
    def __init__(self, database: Database) -> None:
        self.database = database

    def registry(self) -> Registry:
        result = Registry()
        for kind in ["consume_event", "maintenance", "orchestrate"]:
            result.register(
                JobDefinition("notifications." + kind, 1, Request, Result, self.handle, 3600, 3)
            )
        return result

    async def handle(self, ctx: ExecutionContext, payload: BaseModel) -> Result:
        req = Request.model_validate(payload.model_dump())
        kind = ctx.job.job_type.removeprefix("notifications.")
        if kind == "orchestrate":
            from cve_notification.orchestration import trigger

            await trigger(self.database, req.notification_id)

        async def commit(s: AsyncSession) -> Result:
            if kind == "consume_event":
                return Result(count=await self.consume(s, req, ctx.job.correlation_id))
            if kind == "maintenance":
                return Result(count=await self.maintenance(s, ctx.job.correlation_id))
            return Result(count=1)

        result = await ctx.complete(commit)
        assert isinstance(result, Result)
        return result

    async def consume(self, s: AsyncSession, req: Request, correlation: UUID) -> int:
        if req.event_id is None:
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        await s.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key,19))"),
            {"key": "notification-event:" + str(req.event_id)},
        )
        if await one(
            s,
            "SELECT event_id FROM automation.notification_event_receipts WHERE event_id=:id",
            id=req.event_id,
        ):
            return 0
        event = await one(s, "SELECT * FROM automation.event_outbox WHERE id=:id", id=req.event_id)
        if event is None:
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        if event["source"] == "cve-status":
            from cve_notification.status_alerts import consume

            count, outcome = await consume(s, event, correlation)
            await self.receipt(s, event["id"], outcome)
            return count
        kind = event["event_type"].rsplit(".", 1)[-1]
        payload = event["payload"]
        valid = (
            kind in EVENTS
            and (
                event["source"] in {"cve-findings", "cve-api"}
                or event["source"] == "cve-notification"
                and event["event_type"] == "notification.exception_approaching"
            )
            and event["schema_version"] == 1
            and event["aggregate_type"] == "finding"
            and payload.get("schema_version") == 1
            and str(payload.get("finding_id")) == event["aggregate_id"]
        )
        if not valid:
            await self.receipt(s, event["id"], "unsupported_event")
            return 0
        finding = await one(
            s,
            "SELECT f.*,s.created_by AS server_owner_id FROM findings.current_findings f "
            "JOIN inventory.servers s ON s.id=f.server_id WHERE f.id=:id AND f.model_version=2",
            id=UUID(event["aggregate_id"]),
        )
        if (
            finding is None
            or str(payload.get("server_id")) != str(finding["server_id"])
            or payload.get("cve_id") != finding["cve_id"]
        ):
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        from cve_notification.reports import track

        await track(s, event, finding)
        await self.receipt(s, event["id"], "server_scan_batched")
        return 0

    async def receipt(self, s: AsyncSession, event: UUID, outcome: str) -> None:
        await s.execute(
            text(
                "INSERT INTO automation.notification_event_receipts(event_id,outco"
                "me) VALUES(:event,:outcome) ON CONFLICT DO NOTHING"
            ),
            {"event": event, "outcome": outcome},
        )

    async def exception_warnings(self, s: AsyncSession, correlation: UUID) -> None:
        current_rules = await rows(
            s,
            "SELECT DISTINCT ON (rule_key) config FROM "
            "automation.notification_rules ORDER BY rule_key,version DESC",
        )
        rules = [Rule.model_validate(r["config"]) for r in current_rules]
        warning = max(
            (
                r.exception_warning_hours
                for r in rules
                if r.enabled and "exception_approaching" in r.event_types
            ),
            default=0,
        )
        if not warning:
            return
        exceptions = await rows(
            s,
            (
                "SELECT e.*,f.server_id,f.cve_id,f.current_episode_"
                "id,f.version,f.status,f.latest_matching_status,f.c"
                "urrent_priority FROM automation.notification_due_e"
                "xceptions e JOIN findings.findings f ON f.id=e.fin"
                "ding_id WHERE e.valid_until<=clock_timestamp()+mak"
                "e_interval(hours=>:hours) AND NOT EXISTS(SELECT 1 "
                "FROM automation.notification_exception_warnings w "
                "WHERE w.exception_id=e.id) ORDER BY e.valid_until,"
                "e.id LIMIT 100"
            ),
            hours=warning,
        )
        for e in exceptions:
            await s.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key,19))"),
                {"key": "notification-exception:" + str(e["id"])},
            )
            if await one(
                s,
                (
                    "SELECT 1 AS present FROM automation.notification_e"
                    "xception_warnings WHERE exception_id=:id"
                ),
                id=e["id"],
            ):
                continue
            event_id = uuid4()
            payload = {
                "finding_id": str(e["finding_id"]),
                "server_id": str(e["server_id"]),
                "cve_id": e["cve_id"],
                "episode_id": str(e["current_episode_id"]),
                "change_type": "exception_approaching",
                "lifecycle_status": e["status"],
                "matching_status": e["latest_matching_status"],
                "priority": e["current_priority"],
                "row_version": e["version"],
                "schema_version": 1,
                "correlation_id": str(correlation),
                "occurred_at": datetime.now(UTC).isoformat(),
                "exception_id": str(e["id"]),
            }
            await s.execute(
                text(
                    "SELECT automation.emit_event(:event,'notification."
                    "exception_approaching',1,'cve-notification','findi"
                    "ng',:finding,:version,CAST(:payload AS jsonb),:key"
                    ",:correlation)"
                ),
                {
                    "event": event_id,
                    "finding": str(e["finding_id"]),
                    "version": e["version"],
                    "payload": json.dumps(payload),
                    "key": "notification-exception:" + str(e["id"]),
                    "correlation": correlation,
                },
            )
            await s.execute(
                text(
                    "INSERT INTO automation.notification_exception_warn"
                    "ings(exception_id,event_id) VALUES(:id,:event)"
                ),
                {"id": e["id"], "event": event_id},
            )

    async def maintenance(self, s: AsyncSession, correlation: UUID) -> int:
        from cve_notification.reports import maintain

        await maintain(s, correlation)
        await self.exception_warnings(s, correlation)
        now = datetime.now(UTC)
        pending = await rows(
            s,
            (
                "SELECT * FROM automation.notification_intents WHERE digest_id IS "
                "NULL AND\n         ((status IN ('ready','deferred','retryable_fail"
                "ure') AND scheduled_at<=clock_timestamp())\n         OR (status IN"
                " ('leased','submitting') AND lease_until<clock_timestamp())) ORDE"
                "R BY scheduled_at,id LIMIT 100 FOR UPDATE SKIP LOCKED"
            ),
        )
        for n in pending:
            if n["status"] == "submitting":
                await change(s, n, "submission_uncertain", "expired_smtp_lease")
                continue
            if n["status"] == "leased":
                await change(s, n, "ready", "expired_pre_submit_lease")
            elif n["status"] != "ready":
                await change(s, n, "ready", "due_for_orchestration")
            live = await one(
                s,
                (
                    "SELECT id FROM automation.notification_workflow_runs WHERE notifi"
                    "cation_id=:id AND state IN ('requested','executing') AND expires_"
                    "at>clock_timestamp()"
                ),
                id=n["id"],
            )
            if not live:
                await enqueue(
                    s,
                    "orchestrate",
                    {"notification_id": n["id"]},
                    str(n["id"]) + ":" + str(int(now.timestamp()) // 60),
                    correlation,
                )
        await s.execute(
            text(
                "UPDATE automation.notification_workflow_runs SET state='failed',c"
                "ompleted_at=clock_timestamp() WHERE state IN ('requested','execut"
                "ing') AND expires_at<clock_timestamp()"
            )
        )
        return len(pending)
