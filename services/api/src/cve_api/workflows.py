"""Administrator view/control of n8n-owned application stages; no direct task release."""

from typing import Any, Literal
from uuid import UUID

from cve_common.jobs.contracts import Payload
from cve_findings.repository import one, rows
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field
from sqlalchemy import text

from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.errors import Denied
from cve_api.findings.service import Findings

router = APIRouter(
    prefix="/api/v1/dashboard/orchestration",
    tags=["orchestration"],
    dependencies=[Depends(require_permission("cve:read"))],
)


class UpdateSettings(Payload):
    auto_updates: bool
    update_interval: int = Field(ge=300, le=86400)


@router.get("")
async def overview(request: Request) -> Any:
    async with Findings(transport(request)[0]).operation(
        request.cookies.get(SESSION_COOKIE), None, "cve:read"
    ) as (session, actor):
        if not actor.administrator:
            raise Denied()
        summary = await one(session, "SELECT automation.workflow_summary() AS value")
        assert summary
        runs = await rows(
            session,
            """
WITH latest AS MATERIALIZED (
 SELECT r.* FROM automation.workflow_runs r WHERE EXISTS(
 SELECT 1 FROM automation.workflow_requests w JOIN automation.jobs j ON j.id=w.job_id
 WHERE w.correlation_id=r.correlation_id AND (j.job_type NOT IN
 ('status.collect','findings.maintenance','notifications.maintenance')
 OR j.creator_role='api_security'))
 ORDER BY r.created_at DESC LIMIT 20
)
SELECT r.correlation_id,r.created_at,r.paused,r.cancelled,
 count(*) FILTER(WHERE j.status='pending') AS waiting,
 count(*) FILTER(WHERE j.status='running') AS running,
 count(*) FILTER(WHERE j.status IN ('queued','retry_pending')) AS queued,
 count(*) FILTER(WHERE j.status IN ('failed','timed_out')) AS failed,
 array_agg(DISTINCT w.stage) AS stages,max(w.released_at) AS last_release
FROM latest r JOIN automation.workflow_requests w USING(correlation_id)
JOIN automation.jobs j ON j.id=w.job_id
GROUP BY r.correlation_id,r.created_at,r.paused,r.cancelled ORDER BY r.created_at DESC
""",
        )
        queue_items = await rows(
            session,
            """
SELECT id,sequence,kind,producer,message_type,state,created_at,execution_id,error_code
FROM automation.n8n_queue WHERE state IN ('pending','processing','failed')
ORDER BY sequence LIMIT 25
""",
        )
        return {
            **summary["value"],
            "queue_items": queue_items,
            "runs": runs,
            "can_manage": actor.administrator and "cve:update" in actor.permissions,
        }


@router.put("/settings")
async def settings(payload: UpdateSettings, request: Request) -> Any:
    async with Findings(transport(request)[0]).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "cve:update"
    ) as (session, actor):
        if not actor.administrator:
            raise Denied()
        await session.execute(
            text("""
UPDATE automation.workflow_settings SET auto_updates=:enabled,update_interval=:interval,
 next_update_at=clock_timestamp()+make_interval(secs=>:interval),updated_at=clock_timestamp()
WHERE singleton
"""),
            {"enabled": payload.auto_updates, "interval": payload.update_interval},
        )
        await session.execute(
            text("""
INSERT INTO security.audit_log(actor_user_id,action,object_type,outcome,metadata,auth_runtime)
VALUES(:actor,'workflow.settings_changed','workflow_schedule','success',
jsonb_build_object('auto_updates',:enabled,'interval',:interval),true)
"""),
            {
                "actor": actor.user_id,
                "enabled": payload.auto_updates,
                "interval": payload.update_interval,
            },
        )
        value = await one(session, "SELECT automation.workflow_summary() AS value")
        assert value
        return value["value"]


@router.post("/runs/{correlation}/{action}")
async def control(
    correlation: UUID, action: Literal["pause", "resume", "cancel"], request: Request
) -> Any:
    async with Findings(transport(request)[0]).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "cve:update"
    ) as (session, actor):
        if not actor.administrator:
            raise Denied()
        result = await one(
            session,
            "SELECT automation.workflow_run_control(:id,:action) AS controlled",
            id=correlation,
            action=action,
        )
        if not result or not result["controlled"]:
            raise HTTPException(409, "Workflow transition unavailable")
        await session.execute(
            text("""
INSERT INTO security.audit_log
(actor_user_id,action,object_type,object_id,outcome,metadata,auth_runtime)
VALUES(:actor,'workflow.run_controlled','workflow_run',:id,'success',
jsonb_build_object('action',CAST(:action AS text)),true)
"""),
            {"actor": actor.user_id, "id": str(correlation), "action": action},
        )
        return {"controlled": True}
