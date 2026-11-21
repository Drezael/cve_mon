"""Finite role management; system roles and privileged grants are never editable as JSON."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from starlette.responses import Response

from cve_api.auth.dependencies import csrf_for
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.principal import Principal
from cve_api.users.router import service
from cve_api.users.schemas import Version

from .schemas import RoleCreate, RolePatch

router = APIRouter(prefix="/api/v1/dashboard/admin/roles", tags=["role-administration"])


@router.get("")
async def roles(
    request: Request, _actor: Annotated[Principal, Depends(require_permission("role:list"))]
) -> list[dict[str, Any]]:
    return await service(request).role_list(request.cookies.get(SESSION_COOKIE))


@router.get("/{role_id}")
async def role(
    request: Request,
    role_id: UUID,
    _actor: Annotated[Principal, Depends(require_permission("role:list"))],
) -> dict[str, Any]:
    return (await service(request).role_list(request.cookies.get(SESSION_COOKIE), role_id))[0]


@router.post("", status_code=201)
async def create(
    request: Request,
    body: RoleCreate,
    _actor: Annotated[Principal, Depends(require_permission("role:create"))],
) -> dict[str, Any]:
    return await service(request).role_save(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), body
    )


@router.patch("/{role_id}")
async def update(
    request: Request,
    role_id: UUID,
    body: RolePatch,
    _actor: Annotated[Principal, Depends(require_permission("role:update"))],
) -> dict[str, Any]:
    return await service(request).role_save(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), body, role_id
    )


@router.delete("/{role_id}", status_code=204)
async def remove(
    request: Request,
    role_id: UUID,
    body: Version,
    _actor: Annotated[Principal, Depends(require_permission("role:delete"))],
) -> Response:
    await service(request).role_delete(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), role_id, body
    )
    return Response(status_code=204)
