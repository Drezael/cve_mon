"""Dashboard routes; mandatory service revalidation complements transport dependencies."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from cve_api.administration.service import InventoryAdministration
from cve_api.administration.versioning import etag
from cve_api.auth.dependencies import transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.principal import Principal
from cve_api.servers.projections import ServerPage, ServerRead

router = APIRouter(prefix="/api/v1/dashboard", tags=["server-administration"])


def service(request: Request) -> InventoryAdministration:
    return InventoryAdministration(transport(request)[0])


def tagged(response: Response, result: dict[str, Any]) -> dict[str, Any]:
    response.headers["ETag"] = etag(result["version"])
    return result


@router.get("/servers", response_model=ServerPage)
@router.get("/admin/servers", response_model=ServerPage)
async def list_servers(
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("server:read"))],
    search: str = Query(default="", max_length=128),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
    group_id: UUID | None = None,
    environment: str | None = Query(default=None, max_length=64),
    criticality: str | None = None,
    exposure: str | None = None,
    status: str = "active",
    sort: str = "manual",
) -> dict[str, Any]:
    return await service(request).list_servers(
        request.cookies.get(SESSION_COOKIE),
        search=search,
        limit=limit,
        offset=offset,
        group_id=group_id,
        environment=environment,
        criticality=criticality,
        exposure=exposure,
        status=status,
        sort=sort,
    )


@router.get("/servers/{server_id}", response_model=ServerRead)
async def server_detail(
    request: Request,
    response: Response,
    server_id: UUID,
    _actor: Annotated[Principal, Depends(require_permission("server:read"))],
) -> dict[str, Any]:
    return tagged(
        response,
        await service(request).get(request.cookies.get(SESSION_COOKIE), "server", server_id),
    )
