"""Delegation and target boundaries beyond a permission name."""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.repository import one

from .errors import Denied
from .permissions import DELEGABLE
from .principal import Principal


async def target_allowed(
    session: AsyncSession, actor: Principal, target: UUID
) -> dict[str, object]:
    row = await one(
        session,
        ("SELECT id,status,version,auth_version FROM security.users WHERE id=:u FOR UPDATE"),
        u=target,
    )
    if row is None:
        raise Denied(404, "invisible_target")
    privileged = await one(
        session,
        (
            "SELECT EXISTS(SELECT 1 FROM security.user_roles ur JOIN"
            " security.roles r ON r.id=ur.role_id WHERE ur.user_id=:"
            "u AND r.code IN ('admin','user_admin')) AS protected"
        ),
        u=target,
    )
    if not actor.administrator and privileged and privileged["protected"]:
        raise Denied(404, "protected_target")
    return row


def custom_permissions(values: list[str]) -> None:
    if len(values) != len(set(values)) or not set(values) <= DELEGABLE:
        raise Denied(422, "nondelegable_permission")
