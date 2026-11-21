"""Administrative ACLs and own effective permissions, without Phase-10 server CRUD."""

from dataclasses import asdict
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request

from cve_api.auth.dependencies import csrf_for
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.permissions import CATALOG
from cve_api.authorization.principal import Principal
from cve_api.users.router import service

from .schemas import ReplaceAccess

router = APIRouter(tags=["server-access"])


@router.get("/api/v1/dashboard/admin/server-access/{server_id}")
async def read(
    request: Request,
    server_id: UUID,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).access_get(request.cookies.get(SESSION_COOKIE), server_id)


@router.put("/api/v1/dashboard/admin/server-access/{server_id}")
async def replace(
    request: Request,
    server_id: UUID,
    body: ReplaceAccess,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).access_replace(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), server_id, body
    )


@router.get("/api/v1/dashboard/me/permissions")
async def own(request: Request) -> dict[str, Any]:
    return await service(request).effective(request.cookies.get(SESSION_COOKIE))


@router.get("/api/v1/dashboard/admin/permissions")
async def catalog(
    _request: Request, _actor: Annotated[Principal, Depends(require_permission("permission:read"))]
) -> list[dict[str, object]]:
    return [asdict(spec) for spec in CATALOG.values()]
