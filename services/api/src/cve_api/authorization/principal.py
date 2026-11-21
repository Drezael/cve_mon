"""Immutable verified browser principal, rebuilt from PostgreSQL on every service call."""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.repository import one
from cve_api.auth.service import AuthService


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    session_id: UUID
    status: str
    authentication: str
    mfa_verified: bool
    authorization_version: int
    roles: frozenset[str]
    permissions: frozenset[str]

    @property
    def administrator(self) -> bool:
        return "admin" in self.roles


async def load_principal(
    auth: AuthService, session: AsyncSession, cookie: str | None, csrf: str | None = None
) -> tuple[Principal, dict[str, Any]]:
    current = await auth.resolve(session, cookie, csrf, full=True, restricted=True)
    row = await one(
        session,
        (
            "SELECT coalesce(array_agg(DISTINCT r.code),'{}') AS rol"
            "es, coalesce(array_agg(DISTINCT p.code) FILTER(WHERE p."
            "identity_type='human'),'{}') AS permissions FROM securi"
            "ty.user_roles ur JOIN security.roles r ON r.id=ur.role_"
            "id LEFT JOIN security.role_permissions rp ON rp.role_id"
            "=r.id LEFT JOIN security.permissions p ON p.code=rp.per"
            "mission_code WHERE ur.user_id=:u"
        ),
        u=current["user"]["id"],
    )
    assert row is not None
    permissions = set(row["permissions"])
    if "server:inventory:manage" in permissions:
        permissions.update(
            {
                "server:read",
                "server:create",
                "server:update",
                "group:read",
                "inventory:read",
                "finding:read",
                "cve:read",
                "security:overview:read",
            }
        )
    return Principal(
        current["user"]["id"],
        current["id"],
        current["user"]["status"],
        current["auth_state"],
        current["mfa_verified_at"] is not None,
        current["user"]["auth_version"],
        frozenset(row["roles"]),
        frozenset(permissions),
    ), current
