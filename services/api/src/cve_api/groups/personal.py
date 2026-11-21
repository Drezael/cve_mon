"Private, many-to-many organization; group membership never grants server access."

import json
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.administration.service import rows
from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.repository import execute, one
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.errors import Denied
from cve_api.authorization.object_access import predicate
from cve_api.authorization.principal import Principal
from cve_api.findings.service import Findings
from cve_api.groups.schemas import GroupCreate
from cve_api.servers.schemas import Strict

router = APIRouter(prefix="/api/v1/dashboard", tags=["personal-server-groups"])


class GroupWrite(GroupCreate):
    version: int = Field(ge=0)


class Revision(Strict):
    version: int = Field(ge=0)


class MembershipWrite(Revision):
    group_ids: list[UUID] = Field(max_length=500)

    @model_validator(mode="after")
    def unique(self) -> "MembershipWrite":
        if len(self.group_ids) != len(set(self.group_ids)):
            raise ValueError("Duplicate groups")
        return self


async def own_group(s: AsyncSession, actor: Principal, gid: UUID) -> dict[str, Any]:
    group = await one(
        s,
        (
            "SELECT * FROM inventory.server_groups WHERE id=:id AND owner_id=:owner AND "
            "status='active'"
        ),
        id=gid,
        owner=actor.user_id,
    )
    if not group:
        raise Denied(404)
    return group


async def lock(s: AsyncSession, actor: Principal, version: int) -> None:
    # Match the inventory mutation lock order (security lock, inventory lock).
    await execute(s, "SELECT pg_advisory_xact_lock(1010001)")
    await execute(
        s,
        (
            "INSERT INTO inventory.personal_group_revisions(owner_id) VALUES(:owner) ON "
            "CONFLICT DO NOTHING"
        ),
        owner=actor.user_id,
    )
    current = await one(
        s,
        ("SELECT version FROM inventory.personal_group_revisions WHERE owner_id=:owner FOR UPDATE"),
        owner=actor.user_id,
    )
    if not current or current["version"] != version:
        raise Denied(409, "stale_version")


async def changed(
    s: AsyncSession,
    actor: Principal,
    action: str,
    target: UUID,
    details: dict[str, Any] | None = None,
) -> None:
    await execute(
        s,
        ("UPDATE inventory.personal_group_revisions SET version=version+1 WHERE owner_id=:owner"),
        owner=actor.user_id,
    )
    await execute(
        s,
        (
            "INSERT INTO "
            "security.audit_log(actor_user_id,action,object_type,object_id,outcome,metadata) "
            "VALUES(:owner,:action,'server_group',:target,'success',CAST(:details AS jsonb))"
        ),
        owner=actor.user_id,
        action="personal_groups." + action,
        target=str(target),
        details=json.dumps(details or {}, default=str),
    )


async def listing(s: AsyncSession, actor: Principal) -> dict[str, Any]:
    await execute(s, "SELECT pg_advisory_xact_lock_shared(1010001)")
    scope, params = predicate(actor)
    params["owner"] = actor.user_id
    groups = await rows(
        s,
        (
            "SELECT id,name,description FROM inventory.server_groups WHERE "
            "owner_id=:owner AND status='active' ORDER BY lower(name),id"
        ),
        **params,
    )
    members = await rows(
        s,
        (
            "SELECT m.group_id,m.server_id FROM inventory.server_group_memberships m "
            "JOIN inventory.server_groups g ON g.id=m.group_id JOIN inventory.servers s "
            "ON s.id=m.server_id WHERE g.owner_id=:owner AND g.status='active' AND "
            "s.status='active' AND "
        )
        + scope,
        **params,
    )
    by_group: dict[UUID, list[UUID]] = {}
    for m in members:
        by_group.setdefault(m["group_id"], []).append(m["server_id"])
    for group in groups:
        group["server_ids"] = by_group.get(group["id"], [])
    revision = await one(
        s,
        "SELECT version FROM inventory.personal_group_revisions WHERE owner_id=:owner",
        owner=actor.user_id,
    )
    return {"items": groups, "version": revision["version"] if revision else 0}


def service(request: Request) -> Findings:
    return Findings(transport(request)[0])


@router.get("/groups")
async def groups(request: Request) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "server:read"
    ) as (s, actor):
        return await listing(s, actor)


@router.post("/groups", status_code=201)
async def create(request: Request, body: GroupWrite) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "server:read"
    ) as (s, actor):
        await lock(s, actor, body.version)
        count = await one(
            s,
            "SELECT count(*) n FROM inventory.server_groups WHERE owner_id=:owner",
            owner=actor.user_id,
        )
        if count and count["n"] >= 500:
            raise Denied(422, "group_limit")
        group = await one(
            s,
            (
                "INSERT INTO "
                "inventory.server_groups(name,description,owner_id,created_by,updated_by) "
                "VALUES(:name,:description,:owner,:owner,:owner) RETURNING id"
            ),
            name=body.name,
            description=body.description,
            owner=actor.user_id,
        )
        assert group
        await changed(s, actor, "created", group["id"])
        return await listing(s, actor)


@router.put("/groups/{gid}")
async def update(gid: UUID, request: Request, body: GroupWrite) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "server:read"
    ) as (s, actor):
        await lock(s, actor, body.version)
        await own_group(s, actor, gid)
        await execute(
            s,
            (
                "UPDATE inventory.server_groups SET "
                "name=:name,description=:description,updated_by=:owner,version=version+1 "
                "WHERE id=:id AND owner_id=:owner"
            ),
            id=gid,
            owner=actor.user_id,
            name=body.name,
            description=body.description,
        )
        await changed(s, actor, "updated", gid)
        return await listing(s, actor)


@router.delete("/groups/{gid}")
async def delete(gid: UUID, request: Request, body: Revision) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "server:read"
    ) as (s, actor):
        await lock(s, actor, body.version)
        await own_group(s, actor, gid)
        await execute(
            s,
            "DELETE FROM inventory.server_groups WHERE id=:id AND owner_id=:owner",
            id=gid,
            owner=actor.user_id,
        )
        await changed(s, actor, "deleted", gid)
        return await listing(s, actor)


@router.put("/servers/{sid}/groups")
async def assign(sid: UUID, request: Request, body: MembershipWrite) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "server:read"
    ) as (s, actor):
        await lock(s, actor, body.version)
        scope, params = predicate(actor)
        server = await one(
            s,
            "SELECT s.id FROM inventory.servers s WHERE s.id=:sid AND s.status='active' AND "
            + scope,
            sid=sid,
            **params,
        )
        if not server:
            raise Denied(404)
        for gid in body.group_ids:
            await own_group(s, actor, gid)
        await execute(
            s,
            (
                "DELETE FROM inventory.server_group_memberships m USING "
                "inventory.server_groups g WHERE m.group_id=g.id AND m.server_id=:sid AND "
                "g.owner_id=:owner"
            ),
            sid=sid,
            owner=actor.user_id,
        )
        if body.group_ids:
            await execute(
                s,
                (
                    "INSERT INTO inventory.server_group_memberships(server_id,group_id) SELECT "
                    ":sid,id FROM inventory.server_groups WHERE id=ANY(:ids) AND owner_id=:owner"
                ),
                sid=sid,
                ids=body.group_ids,
                owner=actor.user_id,
            )
        await changed(s, actor, "assigned", sid, {"group_ids": body.group_ids})
        return await listing(s, actor)
