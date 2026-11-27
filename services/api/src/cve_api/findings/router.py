"""Authenticated finding API under the existing dashboard origin and ingress gate."""

from typing import Any, Literal
from uuid import UUID, uuid4

from cve_findings.contracts import (
    Assignment,
    ExceptionRequest,
    Mitigation,
    Note,
    PolicyRequest,
    Reason,
    Review,
    Triage,
)
from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import text

from cve_api.administration.versioning import etag
from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.findings.service import Findings

router = APIRouter(
    prefix="/api/v1/findings",
    tags=["findings"],
    dependencies=[Depends(require_permission("finding:read"))],
)


def service(request: Request) -> Findings:
    return Findings(transport(request)[0])


@router.get("/active-count")
async def active_count(request: Request) -> dict[str, int]:
    from cve_common.database.queries import one

    from cve_api.authorization.object_access import predicate

    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "finding:read"
    ) as (session, actor):
        allowed, params = predicate(actor, "finding:read")
        result = await one(
            session,
            "SELECT count(*) AS count FROM findings.findings f JOIN inventory.servers s "
            "ON s.id=f.server_id WHERE s.status='active' "
            "AND f.status IN ('open','in_progress') AND " + allowed,
            **params,
        )
        assert result
        return {"count": result["count"]}


@router.get("")
@router.get("/summary")
async def list_findings(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
    sort: Literal[
        "priority", "first_detected", "last_evaluated", "deadline", "server", "cve"
    ] = "priority",
    direction: Literal["asc", "desc"] = "asc",
    server_id: UUID | None = None,
    group_id: UUID | None = None,
    lifecycle: Literal["open", "in_progress", "resolved", "closed"] | None = None,
    priority: Literal["critical", "high", "medium", "low", "unrated"] | None = None,
    cve_id: str | None = Query(None, pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$", max_length=256),
    overdue: bool | None = None,
    stale: bool | None = None,
    assigned: bool | None = None,
    assignee: UUID | None = None,
    exception: bool | None = None,
    kev: bool | None = None,
    archived: bool | None = None,
    matching_status: Literal[
        "affected", "not_affected", "potentially_affected", "unknown", "not_applicable"
    ]
    | None = None,
) -> dict[str, Any]:
    filters = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "direction": direction,
        "server_id": server_id,
        "group_id": group_id,
        "lifecycle": lifecycle,
        "priority": priority,
        "cve_id": cve_id,
        "overdue": overdue,
        "stale": stale,
        "assigned": assigned,
        "assignee": assignee,
        "exception": exception,
        "kev": kev,
        "archived": archived,
        "matching_status": matching_status,
    }
    return await service(request).list(
        request.cookies.get(SESSION_COOKIE), filters, summary=request.url.path.endswith("/summary")
    )


@router.get("/policies")
async def policies(request: Request) -> dict[str, Any]:
    api = service(request)
    async with api.operation(
        request.cookies.get(SESSION_COOKIE), None, "finding:policy:manage"
    ) as (s, _):
        result = (
            (
                await s.execute(
                    text(
                        (
                            "SELECT p.* FROM findings.active_policy a JOIN findings.policy_"
                            "versions p ON p.id=a.policy_id"
                        )
                    )
                )
            )
            .mappings()
            .one()
        )
        return dict(result)


@router.post("/policies")
async def approve_policy(request: Request, payload: PolicyRequest) -> dict[str, Any]:
    api = service(request)
    async with api.operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "finding:policy:manage"
    ) as (s, actor):
        if payload.configuration.automatic_resolution:
            from cve_api.authorization.errors import Denied

            raise Denied(422, "automatic_resolution_not_supported")
        value = (
            await s.execute(
                text(
                    "SELECT findings.approve_policy(:session,:label,CAST(:configuration"
                    " AS jsonb),:reason,:correlation)"
                ),
                {
                    "session": actor.session_id,
                    "label": payload.label,
                    "configuration": payload.configuration.model_dump_json(),
                    "reason": payload.reason,
                    "correlation": uuid4(),
                },
            )
        ).scalar_one()
        return {"policy_id": value}


@router.get("/{finding_id}")
async def detail(request: Request, response: Response, finding_id: UUID) -> dict[str, Any]:
    value = await service(request).detail(request.cookies.get(SESSION_COOKIE), finding_id)
    response.headers["ETag"] = etag(value["version"])
    return value


@router.get("/{finding_id}/{section}")
async def related(
    request: Request,
    finding_id: UUID,
    section: Literal[
        "history",
        "episodes",
        "evidence",
        "exceptions",
        "notes",
        "reviews",
        "mitigations",
        "assignments",
        "priority",
        "deadlines",
    ],
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
    result_id: UUID | None = None,
) -> dict[str, Any]:
    return await service(request).related(
        request.cookies.get(SESSION_COOKIE), finding_id, section, limit, offset, result_id
    )


async def mutate(
    request: Request,
    response: Response,
    identity: UUID,
    action: str,
    payload: Any,
    permission: str = "finding:update",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = await service(request).command(
        request.cookies.get(SESSION_COOKIE),
        csrf_for(request),
        identity,
        action,
        payload,
        request.headers.get("if-match"),
        permission=permission,
        extra=extra,
    )
    response.headers["ETag"] = etag(value["version"])
    return value


@router.post("/{finding_id}/triage")
async def triage(
    request: Request, response: Response, finding_id: UUID, payload: Triage
) -> dict[str, Any]:
    return await mutate(request, response, finding_id, "triage", payload)


@router.post("/{finding_id}/notes")
async def note(
    request: Request, response: Response, finding_id: UUID, payload: Note
) -> dict[str, Any]:
    return await mutate(request, response, finding_id, "note", payload)


@router.post("/{finding_id}/assignments")
async def assign(
    request: Request, response: Response, finding_id: UUID, payload: Assignment
) -> dict[str, Any]:
    return await mutate(request, response, finding_id, "assign", payload)


@router.post("/{finding_id}/reviews")
async def review(
    request: Request, response: Response, finding_id: UUID, payload: Review
) -> dict[str, Any]:
    return await mutate(
        request,
        response,
        finding_id,
        "review",
        payload,
        "finding:review:confirm"
        if payload.decision == "confirmed_false_positive"
        else "finding:update",
    )


@router.post("/{finding_id}/mitigations")
async def mitigate(
    request: Request, response: Response, finding_id: UUID, payload: Mitigation
) -> dict[str, Any]:
    return await mutate(request, response, finding_id, "mitigation", payload)


@router.post("/{finding_id}/exceptions")
async def exception_request(
    request: Request, response: Response, finding_id: UUID, payload: ExceptionRequest
) -> dict[str, Any]:
    return await mutate(request, response, finding_id, "exception_request", payload)


@router.post("/{finding_id}/exceptions/{exception_id}/{action}")
async def exception_decide(
    request: Request,
    response: Response,
    finding_id: UUID,
    exception_id: UUID,
    action: Literal["approve", "reject", "revoke"],
    payload: Reason,
) -> dict[str, Any]:
    return await mutate(
        request,
        response,
        finding_id,
        "exception_" + action,
        payload,
        "finding:exception:approve",
        {"exception_id": str(exception_id)},
    )


@router.post("/{finding_id}/close")
async def close(
    request: Request, response: Response, finding_id: UUID, payload: Reason
) -> dict[str, Any]:
    return await mutate(request, response, finding_id, "close", payload, "finding:close")
