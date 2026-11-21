"""Protected administrative user API, without credentials or arbitrary profile properties."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.administration import Administration
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.principal import Principal

from .schemas import AssignRoles, UserCreate, UserPatch, Version

router = APIRouter(prefix="/api/v1/dashboard/admin/users", tags=["user-administration"])


def service(request: Request) -> Administration:
    auth, _ = transport(request)
    return Administration(auth)


@router.get("")
async def list_users(
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("user:list"))],
    search: str = Query(default="", max_length=128),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
) -> dict[str, Any]:
    return await service(request).user_list(
        request.cookies.get(SESSION_COOKIE), search, limit, offset
    )


@router.post("", status_code=201)
async def create_user(
    request: Request,
    body: UserCreate,
    _actor: Annotated[Principal, Depends(require_permission("user:create"))],
) -> dict[str, Any]:
    return await service(request).user_create(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), body
    )


@router.get("/{user_id}")
async def get_user(
    request: Request,
    user_id: UUID,
    _actor: Annotated[Principal, Depends(require_permission("user:read"))],
) -> dict[str, Any]:
    return await service(request).user_get(request.cookies.get(SESSION_COOKIE), user_id)


@router.patch("/{user_id}")
async def patch_user(
    request: Request,
    user_id: UUID,
    body: UserPatch,
    _actor: Annotated[Principal, Depends(require_permission("user:update"))],
) -> dict[str, Any]:
    return await service(request).user_patch(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), user_id, body
    )


@router.put("/{user_id}/roles")
async def assign_roles(
    request: Request,
    user_id: UUID,
    body: AssignRoles,
    _actor: Annotated[Principal, Depends(require_permission("user:role:assign"))],
) -> dict[str, Any]:
    return await service(request).assign_roles(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), user_id, body
    )


@router.get("/{user_id}/permissions")
async def effective(
    request: Request,
    user_id: UUID,
    _actor: Annotated[Principal, Depends(require_permission("user:read"))],
) -> dict[str, Any]:
    return await service(request).effective(request.cookies.get(SESSION_COOKIE), user_id)


@router.post("/{user_id}/mfa-recovery")
async def recover_mfa(
    request: Request,
    user_id: UUID,
    body: Version,
    _actor: Annotated[Principal, Depends(require_permission("user:mfa:recovery"))],
) -> dict[str, Any]:
    return await service(request).recovery_request(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), user_id, body
    )


def add_lifecycle(action: str, permission: str) -> None:
    async def mutate(
        request: Request,
        user_id: UUID,
        body: Version,
        _actor: Annotated[Principal, Depends(require_permission(permission))],
    ) -> dict[str, Any]:
        return await service(request).lifecycle(
            request.cookies.get(SESSION_COOKIE), csrf_for(request), user_id, action, body
        )

    router.add_api_route(
        "/{user_id}/" + action, mutate, methods=["POST"], name="user_" + action.replace("-", "_")
    )


for _action, _permission in [
    ("enable", "user:enable"),
    ("disable", "user:disable"),
    ("archive", "user:archive"),
    ("lock", "user:disable"),
    ("revoke-sessions", "user:session:revoke"),
]:
    add_lifecycle(_action, _permission)
