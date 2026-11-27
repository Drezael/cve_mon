"""Personal scoped history and explicit administrator-only configuration; no send-mail endpoint."""

from typing import Any, Literal
from uuid import UUID, uuid4

from cve_common.database.queries import one, rows
from cve_common.jobs.contracts import Payload
from cve_notification.contracts import Preferences, RuleChange, TemplateChange
from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import Field
from sqlalchemy import text

from cve_api.administration.versioning import etag, expected
from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.errors import Denied
from cve_api.findings.service import Findings

router = APIRouter(
    prefix="/api/v1/dashboard/notifications",
    tags=["notifications"],
    dependencies=[Depends(require_permission("notification:read"))],
)


class PreferenceChange(Payload):
    preferences: Preferences
    reason: str = Field(min_length=3, max_length=1024)


class Evidence(Payload):
    evidence_id: str = Field(min_length=1, max_length=256)
    relay_instance: str = Field(min_length=1, max_length=128)
    message_id: str = Field(min_length=1, max_length=256)
    queue_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9]{5,64}$")
    status: Literal["relay_accepted", "upstream_accepted", "bounced", "delivery_confirmed"]
    source: Literal["postfix", "verified_dsn"]
    reason: str = Field(min_length=3, max_length=1024)


def service(request: Request) -> Findings:
    return Findings(transport(request)[0])


def scope() -> str:
    return """
(n.recipient_user_id=:actor OR :admin) AND (
 :admin OR EXISTS(
  SELECT 1 FROM automation.mail_reports mr
  JOIN automation.mail_report_servers srv ON srv.report_id=mr.id
  WHERE mr.notification_id=n.id AND mr.user_id=:actor
   AND automation.report_server_access(:actor,srv.server_id)
 ) OR (n.finding_id IS NOT NULL AND automation.notification_recipient(:actor,n.finding_id))
 OR (n.kind='digest' AND EXISTS(
  SELECT 1 FROM automation.notification_intents child WHERE child.digest_id=n.id
   AND automation.notification_recipient(:actor,child.finding_id)
 ))
)
"""


@router.get("/preferences")
async def preferences(request: Request, response: Response) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "notification:read"
    ) as (s, actor):
        value = await one(
            s,
            (
                "SELECT version,config,updated_at FROM automation.notification_pre"
                "ferences WHERE user_id=:id"
            ),
            id=actor.user_id,
        )
        response.headers["ETag"] = etag(value["version"] if value else 0)
        return value or {"version": 0, "config": Preferences().model_dump(mode="json")}


@router.put("/preferences")
async def update_preferences(
    payload: PreferenceChange, request: Request, response: Response
) -> Any:
    return await command(
        request, response, "preferences", None, payload.preferences, payload.reason
    )


@router.get("/rules")
async def rules(request: Request) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "notification:rule:read"
    ) as (s, _):
        return {
            "items": await rows(
                s,
                (
                    "SELECT DISTINCT ON (rule_key) * FROM automation.notification_rule"
                    "s ORDER BY rule_key,version DESC"
                ),
            )
        }


@router.post("/rules")
async def create_rule(payload: RuleChange, request: Request, response: Response) -> Any:
    return await command(request, response, "rule", uuid4(), payload.rule, payload.reason)


@router.put("/rules/{identity}")
async def update_rule(
    identity: UUID, payload: RuleChange, request: Request, response: Response
) -> Any:
    return await command(request, response, "rule", identity, payload.rule, payload.reason)


@router.get("/templates")
async def templates(request: Request) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "notification:template:read"
    ) as (s, _):
        return {
            "items": await rows(
                s,
                (
                    "SELECT DISTINCT ON (name,language) * FROM automation.notification"
                    "_templates ORDER BY name,language,version DESC"
                ),
            )
        }


@router.post("/templates")
async def update_template(payload: TemplateChange, request: Request, response: Response) -> Any:
    return await command(request, response, "template", None, payload.template, payload.reason)


async def command(
    request: Request,
    response: Response,
    kind: str,
    identity: UUID | None,
    payload: Payload,
    reason: str,
) -> Any:
    action = "notification:" + ("preferences:update" if kind == "preferences" else kind + ":manage")
    api = service(request)
    csrf = csrf_for(request)
    async with api.operation(request.cookies.get(SESSION_COOKIE), csrf, action) as (s, actor):
        version = (
            0
            if request.headers.get("If-Match") == '"0"'
            else expected(request.headers.get("If-Match"))
        )
        result = (
            await s.execute(
                text(
                    "SELECT automation.notification_command(:session,:kind,:id,:versio"
                    "n,CAST(:config AS jsonb),:reason,:correlation)"
                ),
                {
                    "session": actor.session_id,
                    "kind": kind,
                    "id": identity,
                    "version": version,
                    "config": payload.model_dump_json(),
                    "reason": reason,
                    "correlation": uuid4(),
                },
            )
        ).scalar_one()
        response.headers["ETag"] = etag(result["version"])
        return result


@router.get("/deliveries")
@router.get("/workflows")
async def administration(
    request: Request, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=100000)
) -> Any:
    kind = "workflows" if request.url.path.endswith("/workflows") else "deliveries"
    table = (
        "notification_workflow_runs" if kind == "workflows" else "notification_delivery_attempts"
    )
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE),
        None,
        "notification:" + ("workflow:read" if kind == "workflows" else "delivery:read"),
    ) as (s, _):
        return {
            "items": await rows(
                s,
                "SELECT * FROM automation."
                + table
                + " ORDER BY created_at DESC,id LIMIT :limit OFFSET :offset"
                if kind == "workflows"
                else (
                    "SELECT * FROM automation.notification_delivery_attempts ORDER BY "
                    "started_at DESC,id LIMIT :limit OFFSET :offset"
                ),
                limit=limit,
                offset=offset,
            )
        }


@router.get("")
async def listing(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
    status: Literal[
        "planned",
        "suppressed",
        "deferred",
        "ready",
        "leased",
        "submitting",
        "relay_accepted",
        "retryable_failure",
        "permanent_failure",
        "submission_uncertain",
        "upstream_accepted",
        "bounced",
        "delivery_confirmed",
        "cancelled",
    ]
    | None = None,
    order: Literal["asc", "desc"] = "desc",
) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "notification:read"
    ) as (s, actor):
        params = {
            "actor": actor.user_id,
            "admin": actor.administrator,
            "limit": limit,
            "offset": offset,
            "status": status,
        }
        where = scope() + " AND (CAST(:status AS text) IS NULL OR n.status=:status)"
        values = await rows(
            s,
            (
                "SELECT n.*,f.cve_id,f.server_id,s.display_name AS server_name,f.current_priority "
                "FROM automation.notification_intents n LEFT JOIN findings.current_findings f "
                "ON f.id=n.finding_id "
                "LEFT JOIN inventory.servers s ON s.id=f.server_id WHERE "
            )
            + where
            + " ORDER BY n.created_at "
            + order
            + ",n.id LIMIT :limit OFFSET :offset",
            **params,
        )
        total = await one(
            s,
            "SELECT count(*) AS total FROM automation.notification_intents n WHERE " + where,
            **params,
        )
        return {
            "items": values,
            "total": total["total"] if total else 0,
            "limit": limit,
            "offset": offset,
        }


@router.get("/{identity}")
@router.get("/{identity}/history")
@router.get("/{identity}/attempts")
async def detail(
    identity: UUID,
    request: Request,
    response: Response,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "notification:read"
    ) as (s, actor):
        n = await one(
            s,
            (
                "SELECT n.*,f.cve_id,f.server_id,s.display_name AS server_name,f.current_priority "
                "FROM automation.notification_intents n LEFT JOIN findings.current_findings f "
                "ON f.id=n.finding_id "
                "LEFT JOIN inventory.servers s ON s.id=f.server_id WHERE n.id=:id AND "
            )
            + scope(),
            id=identity,
            actor=actor.user_id,
            admin=actor.administrator,
        )
        if n is None:
            raise Denied(404)
        response.headers["ETag"] = etag(n["version"])
        if request.url.path.endswith("/history"):
            return {
                "items": await rows(
                    s,
                    (
                        "SELECT * FROM automation.notification_history WHERE notification_"
                        "id=:id ORDER BY version LIMIT :limit OFFSET :offset"
                    ),
                    id=identity,
                    limit=limit,
                    offset=offset,
                ),
                "limit": limit,
                "offset": offset,
            }
        if request.url.path.endswith("/attempts"):
            return {
                "items": await rows(
                    s,
                    (
                        "SELECT a.*,r.status,r.reason,r.smtp_code,r.queue_id,r.relay_insta"
                        "nce FROM automation.notification_delivery_attempts a LEFT JOIN au"
                        "tomation.notification_delivery_results r ON r.attempt_id=a.id WHE"
                        "RE a.notification_id=:id ORDER BY attempt LIMIT :limit OFFSET :offset"
                    ),
                    id=identity,
                    limit=limit,
                    offset=offset,
                ),
                "limit": limit,
                "offset": offset,
            }
        return n


@router.post("/{identity}/transport-evidence")
async def evidence(identity: UUID, payload: Evidence, request: Request) -> Any:
    api = service(request)
    async with api.operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "notification:rule:manage"
    ) as (s, actor):
        await s.execute(
            text(
                "SELECT automation.notification_evidence(:session,:id,:evidence,:r"
                "elay,:message,:queue,:status,:source,:reason,:correlation)"
            ),
            {
                "session": actor.session_id,
                "id": identity,
                "evidence": payload.evidence_id,
                "relay": payload.relay_instance,
                "message": payload.message_id,
                "queue": payload.queue_id,
                "status": payload.status,
                "source": payload.source,
                "reason": payload.reason,
                "correlation": uuid4(),
            },
        )
        return {"recorded": True}
