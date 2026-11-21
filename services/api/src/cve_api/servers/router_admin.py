"""Dashboard routes; mandatory service revalidation complements transport dependencies."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from cve_api.administration.service import InventoryAdministration
from cve_api.administration.versioning import etag
from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.errors import Denied
from cve_api.authorization.principal import Principal
from cve_api.groups.schemas import Ordering
from cve_api.servers.projections import ServerRead
from cve_api.servers.schemas import Lifecycle, ServerCreate, ServerPatch

router = APIRouter(prefix="/api/v1/dashboard", tags=["server-administration"])


def service(request: Request) -> InventoryAdministration:
    return InventoryAdministration(transport(request)[0])


def match(request: Request) -> str | None:
    values = request.headers.getlist("if-match")
    if len(values) > 1:
        raise Denied(400, "ambiguous_etag")
    return values[0] if values else None


def tagged(response: Response, result: dict[str, Any]) -> dict[str, Any]:
    response.headers["ETag"] = etag(result["version"])
    return result


@router.post("/admin/servers", status_code=201, response_model=ServerRead)
async def create_server(
    request: Request,
    response: Response,
    body: ServerCreate,
    _actor: Annotated[Principal, Depends(require_permission("server:create"))],
) -> dict[str, Any]:
    return tagged(
        response,
        await service(request).register(
            request.cookies.get(SESSION_COOKIE), csrf_for(request), body
        ),
    )


@router.get("/admin/servers/order")
async def get_server_order(
    request: Request,
    response: Response,
    _actor: Annotated[Principal, Depends(require_permission("server:reorder"))],
) -> dict[str, Any]:
    return tagged(
        response, await service(request).order(request.cookies.get(SESSION_COOKIE), None, "servers")
    )


@router.put("/admin/servers/order")
async def put_server_order(
    request: Request,
    response: Response,
    body: Ordering,
    _actor: Annotated[Principal, Depends(require_permission("server:reorder"))],
) -> dict[str, Any]:
    return tagged(
        response,
        await service(request).order(
            request.cookies.get(SESSION_COOKIE),
            csrf_for(request),
            "servers",
            body,
            match(request),
        ),
    )


@router.get("/admin/servers/{server_id}", response_model=ServerRead)
async def get_server(
    request: Request,
    response: Response,
    server_id: UUID,
    _actor: Annotated[Principal, Depends(require_permission("server:read"))],
) -> dict[str, Any]:
    return tagged(
        response,
        await service(request).get(request.cookies.get(SESSION_COOKIE), "server", server_id),
    )


@router.patch("/admin/servers/{server_id}", response_model=ServerRead)
async def patch_server(
    request: Request,
    response: Response,
    server_id: UUID,
    body: ServerPatch,
    _actor: Annotated[Principal, Depends(require_permission("server:update"))],
) -> dict[str, Any]:
    return tagged(
        response,
        await service(request).patch(
            request.cookies.get(SESSION_COOKIE),
            csrf_for(request),
            "server",
            server_id,
            body,
            match(request),
        ),
    )


@router.post("/admin/servers/{server_id}/archive", response_model=ServerRead)
async def archive_server(
    request: Request,
    response: Response,
    server_id: UUID,
    body: Lifecycle,
    _actor: Annotated[Principal, Depends(require_permission("server:delete"))],
) -> dict[str, Any]:
    return tagged(
        response,
        await service(request).lifecycle(
            request.cookies.get(SESSION_COOKIE),
            csrf_for(request),
            "server",
            server_id,
            False,
            body,
            match(request),
        ),
    )


@router.post("/admin/servers/{server_id}/restore", response_model=ServerRead)
async def restore_server(
    request: Request,
    response: Response,
    server_id: UUID,
    body: Lifecycle,
    _actor: Annotated[Principal, Depends(require_permission("server:restore"))],
) -> dict[str, Any]:
    return tagged(
        response,
        await service(request).lifecycle(
            request.cookies.get(SESSION_COOKIE),
            csrf_for(request),
            "server",
            server_id,
            True,
            body,
            match(request),
        ),
    )
