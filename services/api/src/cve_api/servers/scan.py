"""Manual scans reuse the current inventory and n8n's durable matching gate."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Header, Request

from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.repository import execute, one
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.findings.service import Findings

router = APIRouter(prefix="/api/v1/dashboard/servers", tags=["server-scans"])


@router.post("/{identity}/scan", status_code=202)
async def scan(
    identity: UUID, request: Request, key: Annotated[UUID, Header(alias="Idempotency-Key")]
) -> Any:
    async with Findings(transport(request)[0]).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "server:inventory:manage"
    ) as (session, actor):
        row = await one(
            session,
            "SELECT inventory.request_full_scan(:actor,:server,:key) AS value",
            actor=actor.user_id,
            server=identity,
            key=key,
        )
        assert row
        await execute(
            session,
            "INSERT INTO security.audit_log(actor_user_id,action,object_type,object_id,"
            "outcome,metadata) VALUES(:actor,'inventory.full_scan_requested',"
            "'server',:server,'success','{}'::jsonb)",
            actor=actor.user_id,
            server=str(identity),
        )
        return row["value"]
