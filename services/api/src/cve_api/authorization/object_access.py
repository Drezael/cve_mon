"""ACL filtering precedes search, pagination, counts and group aggregation in SQL."""

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .engine import function_decision
from .errors import Denied
from .permissions import ACL_COLUMNS, CATALOG
from .principal import Principal


def predicate(principal: Principal, action: str = "server:read") -> tuple[str, dict[str, Any]]:
    if not function_decision(principal, action).allow:
        raise Denied()
    scope = CATALOG[action].object_scope
    if scope is None:
        raise Denied(403, "object_scope_required")
    if principal.administrator and scope != "inventory_upload":
        return "true", {}
    return (
        "EXISTS(SELECT 1 FROM security.user_server_access a WHERE a.server_id=s.id "
        "AND a.user_id=:actor AND a." + ACL_COLUMNS[scope] + ")",
        {"actor": principal.user_id},
    )


async def visible_servers(
    session: AsyncSession,
    principal: Principal,
    *,
    search: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    if not 1 <= limit <= 100 or not 0 <= offset <= 100000 or len(search) > 128:
        raise Denied(422)
    allowed, parameters = predicate(principal)
    parameters.update(search=search, limit=limit, offset=offset)
    where = (
        "s.status<>'archived' AND "
        + allowed
        + " AND strpos(lower(s.display_name),lower(:search))>0"
    )
    rows = (
        (
            await session.execute(
                text(
                    ("SELECT s.id,s.display_name FROM inventory.servers s WHERE ")
                    + where
                    + " ORDER BY s.id LIMIT :limit OFFSET :offset"
                ),
                parameters,
            )
        )
        .mappings()
        .all()
    )
    total = (
        await session.execute(
            text("SELECT count(*) FROM inventory.servers s WHERE " + where), parameters
        )
    ).scalar_one()
    return {"items": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}


async def visible_group_counts(session: AsyncSession, principal: Principal) -> list[dict[str, Any]]:
    if not function_decision(principal, "group:read").allow:
        raise Denied()
    allowed, parameters = predicate(principal)
    parameters["group_owner"] = principal.user_id
    rows = (
        (
            await session.execute(
                text(
                    (
                        "SELECT g.id,g.name,count(DISTINCT s.id) AS visible_serv"
                        "ers FROM inventory.server_groups g JOIN inventory.serve"
                        "r_group_memberships m ON m.group_id=g.id JOIN inventory"
                        ".servers s ON s.id=m.server_id WHERE g.status='active' "
                        "AND g.owner_id=:group_owner AND s.status<>'archived' AND "
                    )
                    + allowed
                    + " GROUP BY g.id,g.name ORDER BY g.id"
                ),
                parameters,
            )
        )
        .mappings()
        .all()
    )
    return [dict(r) for r in rows]
