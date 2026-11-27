"""Personal weekly schedule and idempotent on-demand report requests through n8n."""

import json
from typing import Annotated, Any
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cve_common.database.queries import one, rows
from cve_common.jobs.contracts import Payload
from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import Field, field_validator

from cve_api.administration.versioning import etag, expected
from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.findings.service import Findings

router = APIRouter(prefix="/api/v1/dashboard/notifications/reports", tags=["notifications"])


class Schedule(Payload):
    enabled: bool = True
    weekday: int = Field(default=0, ge=0, le=6)
    time: str = Field(default="09:00", pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
    timezone: str = Field(default="Europe/Berlin", max_length=64)

    @field_validator("timezone")
    @classmethod
    def zone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError:
            raise ValueError("Unknown timezone") from None
        return value


def service(request: Request) -> Findings:
    return Findings(transport(request)[0])


@router.get("/schedule", dependencies=[Depends(require_permission("notification:read"))])
async def schedule(request: Request, response: Response) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "notification:read"
    ) as (s, actor):
        result = await one(
            s,
            "SELECT version,configuration,next_run_at,updated_at FROM automation.mail_"
            "report_schedules WHERE user_id=:user",
            user=actor.user_id,
        )
        response.headers["ETag"] = etag(result["version"] if result else 0)
        return result or {
            "version": 0,
            "configuration": Schedule().model_dump(mode="json"),
            "next_run_at": None,
        }


@router.put(
    "/schedule", dependencies=[Depends(require_permission("notification:preferences:update"))]
)
async def save_schedule(body: Schedule, request: Request, response: Response) -> Any:
    version = request.headers.get("if-match")
    wanted = 0 if version == '"0"' else expected(version)
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "notification:preferences:update"
    ) as (s, actor):
        result = await one(
            s,
            "SELECT automation.report_schedule_set(:user,:version,CAST(:cfg AS jsonb)) AS value",
            user=actor.user_id,
            version=wanted,
            cfg=json.dumps(body.model_dump(mode="json")),
        )
        assert result
        response.headers["ETag"] = etag(result["value"]["version"])
        return result["value"]


@router.post(
    "/request",
    status_code=202,
    dependencies=[Depends(require_permission("notification:preferences:update"))],
)
async def request_report(
    request: Request, key: Annotated[UUID, Header(alias="Idempotency-Key")]
) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "notification:preferences:update"
    ) as (s, actor):
        result = await one(
            s,
            "SELECT automation.request_mail_report(:user,:key) AS value",
            user=actor.user_id,
            key=key,
        )
        assert result
        return result["value"]


@router.get("", dependencies=[Depends(require_permission("notification:read"))])
async def history(request: Request) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "notification:read"
    ) as (s, actor):
        return {
            "items": await rows(
                s,
                """SELECT r.id,r.origin,r.state,r.created_at,r.completed_at,r.error_code,
 n.status AS delivery_status,n.reason AS delivery_reason,
 (SELECT count(*) FROM automation.mail_report_servers srv WHERE srv.report_id=r.id) AS server_count
 FROM automation.mail_reports r
 LEFT JOIN automation.notification_intents n ON n.id=r.notification_id
 WHERE r.user_id=:user ORDER BY r.created_at DESC,r.id LIMIT 20""",
                user=actor.user_id,
            )
        }
