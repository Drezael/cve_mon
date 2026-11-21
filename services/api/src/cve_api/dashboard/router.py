"""Same-origin dashboard reads; source identities and permissions are always server-derived."""

from typing import Annotated, Any, Literal
from uuid import UUID

from cve_findings.repository import one
from fastapi import APIRouter, Depends, Query, Request

from cve_api.auth.dependencies import transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.principal import Principal
from cve_api.dashboard.models import Context, Overview, ServerSummaries, ServerSummary, Trends
from cve_api.dashboard.service import Dashboard

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


def service(request: Request) -> Dashboard:
    return Dashboard(transport(request)[0])


@router.get("/overview", response_model=Overview)
@router.get("/overview/coverage", response_model=Overview)
async def overview(
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("security:overview:read"))],
) -> Any:
    return await service(request).overview(request.cookies.get(SESSION_COOKIE))


@router.get("/overview/trends", response_model=Trends)
async def trends(
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("security:overview:read"))],
    days: int = Query(30, ge=1, le=90),
) -> Any:
    return await service(request).trends(request.cookies.get(SESSION_COOKIE), days)


@router.get("/security/servers", response_model=ServerSummaries)
async def servers(
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("server:read"))],
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
    search: str = Query("", max_length=128),
    group_id: UUID | None = None,
    status: Literal["active", "archived"] = "active",
    sort: Literal["manual", "name", "inventory"] = "manual",
    distribution: str | None = Query(None, max_length=128),
) -> Any:
    return await service(request).servers(
        request.cookies.get(SESSION_COOKIE),
        limit=limit,
        offset=offset,
        search=search,
        group=group_id,
        status=status,
        sort=sort,
        distribution=distribution,
    )


@router.get("/security/servers/{identity}", response_model=ServerSummary)
async def server(
    identity: UUID,
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("server:read"))],
    archived: bool = False,
) -> Any:
    values = await service(request).servers(
        request.cookies.get(SESSION_COOKIE),
        identity=identity,
        limit=1,
        offset=0,
        status="archived" if archived else "active",
    )
    return values["items"][0]


@router.get("/security/findings/{identity}/context", response_model=Context)
async def context(
    identity: UUID,
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("finding:read"))],
) -> Any:
    api = service(request)
    async with api.operation(request.cookies.get(SESSION_COOKIE), None, "finding:read") as (
        s,
        actor,
    ):
        f = await api.visible(s, actor, identity)
        value = await one(
            s,
            (
                "SELECT snapshot_id,enrichment_revision_id,rule_ver"
                "sion,created_at,status,result FROM matching.result"
                "_revisions WHERE id=:id"
            ),
            id=f["latest_matching_result_id"],
        )
        assert value
        return {
            "finding_id": identity,
            "snapshot_id": value["snapshot_id"],
            "enrichment_revision_id": value["enrichment_revision_id"],
            "rule_version": value["rule_version"],
            "matched_at": value["created_at"],
            "status": value["status"],
            "coverage": value["result"].get("coverage", {}),
            "components": value["result"].get("components", []),
            "data_quality": value["result"].get("data_quality"),
        }
