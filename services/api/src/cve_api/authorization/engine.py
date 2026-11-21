"""Default-deny human RBAC plus explicit object capabilities, without a stale cache."""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.repository import one

from .permissions import ACL_COLUMNS, CATALOG
from .principal import Principal


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str


def function_decision(principal: Principal, action: str) -> Decision:
    spec = CATALOG.get(action)
    if spec is None:
        return Decision(False, "unknown_action")
    if principal.status != "active" or principal.authentication != "authenticated":
        return Decision(False, "incomplete_identity")
    if action not in principal.permissions:
        return Decision(False, "missing_permission")
    return Decision(True, "explicit_permission")


async def decide(
    session: AsyncSession, principal: Principal, action: str, server_id: UUID | None = None
) -> Decision:
    result = function_decision(principal, action)
    if not result.allow:
        return result
    scope = CATALOG[action].object_scope
    if scope is None:
        return result
    if server_id is None:
        return Decision(False, "object_required")
    exists = await one(
        session,
        ("SELECT id FROM inventory.servers WHERE id=:id AND status<>'archived'"),
        id=server_id,
    )
    if exists is None:
        return Decision(False, "invisible_object")
    # Platform administration explicitly covers reads. Uploads always need their own grant.
    if principal.administrator and scope != "inventory_upload":
        return Decision(True, "platform_administration")
    column = ACL_COLUMNS[scope]
    row = await one(
        session,
        "SELECT "
        + column
        + (" AS allowed FROM security.user_server_access WHERE user_id=:u AND server_id=:s"),
        u=principal.user_id,
        s=server_id,
    )
    return Decision(
        bool(row and row["allowed"]), "explicit_acl" if row and row["allowed"] else "missing_acl"
    )
