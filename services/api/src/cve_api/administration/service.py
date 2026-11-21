"One authenticated PostgreSQL transaction per administrative command or ACL read."

import hashlib
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.errors import AuthError
from cve_api.auth.repository import execute, one
from cve_api.auth.service import AuthService
from cve_api.auth.transactions import security_transaction
from cve_api.authorization.administration import Administration
from cve_api.authorization.engine import function_decision
from cve_api.authorization.errors import Denied
from cve_api.authorization.object_access import predicate
from cve_api.authorization.principal import Principal, load_principal
from cve_api.groups.schemas import Ordering
from cve_api.servers.schemas import Lifecycle, ServerCreate, ServerPatch

from .audit import record
from .versioning import check

SERVER_FIELDS = (
    "id,display_name,description,environment,criticality,exposure,stat"
    "us,primary_group_id,display_order,created_at,updated_at,archived_"
    "at,version"
)


async def rows(s: AsyncSession, query: str, **params: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in (await s.execute(text(query), params)).mappings().all()]


async def bump(s: AsyncSession, scope: str) -> int:
    row = await one(
        s,
        "INSERT INTO dashboard.order_versions(scope,version) VALUES(:scope,2) "
        "ON CONFLICT(scope) DO UPDATE SET version=order_versions.version+1"
        " RETURNING version",
        scope=scope,
    )
    assert row is not None
    return int(row["version"])


async def revision(s: AsyncSession, scope: str) -> int:
    row = await one(
        s, "SELECT version FROM dashboard.order_versions WHERE scope=:scope", scope=scope
    )
    return int(row["version"]) if row else 1


class InventoryAdministration:
    def __init__(self, auth: AuthService) -> None:
        self.auth = auth

    @asynccontextmanager
    async def operation(
        self,
        cookie: str | None,
        csrf: str | None,
        action: str,
        *,
        mutation: bool = False,
        target: UUID | None = None,
    ) -> AsyncIterator[tuple[AsyncSession, Principal]]:
        started = time.monotonic()
        result = 200
        try:
            database = self.auth.administration_database
            if database is None:
                raise AuthError(503)
            async with security_transaction(database, mutation=mutation) as s:
                a, current = await load_principal(self.auth, s, cookie, csrf)
                if not function_decision(a, action).allow:
                    raise Denied()
                if mutation:
                    await self.auth.consume_reauth(s, current)
                    await execute(s, "SELECT pg_advisory_xact_lock(1010001)")
                yield s, a
                if mutation:
                    await execute(s, "SET CONSTRAINTS ALL IMMEDIATE")
        except (Denied, AuthError) as error:
            result = error.status
            if result in {400, 403, 409, 412, 422, 428}:
                await self.denied(cookie, action, target, result)
            raise
        except DBAPIError as error:
            state = getattr(error.orig, "sqlstate", None)
            if isinstance(error, IntegrityError) or state in {"40001", "40P01", "22003"}:
                result = 409
                await self.denied(cookie, action, target, result)
                raise Denied(409, "conflicting_state") from None
            result = 503
            raise
        finally:
            logging.getLogger("cve.administration." + action.replace(":", ".")).info(
                "request",
                extra={
                    "action": action,
                    "status": result,
                    "duration_ms": round((time.monotonic() - started) * 1000, 3),
                },
            )

    async def denied(
        self, cookie: str | None, action: str, target: UUID | None, status: int
    ) -> None:
        await Administration(self.auth).log_denial(cookie, "administration_rejected", target)
        try:
            await self.auth.limits.check(
                "inventory-administration-denied", str(cookie or "")[:36], 10
            )
            assert self.auth.administration_database is not None
            async with security_transaction(self.auth.administration_database) as s:
                a, _ = await load_principal(self.auth, s, cookie)
                await record(
                    s,
                    "denied",
                    a.user_id,
                    target,
                    {"action": action, "status": status},
                    success=False,
                )
        except (AuthError, DBAPIError):
            pass

    async def server(
        self, s: AsyncSession, a: Principal, sid: UUID, *, lock: bool = False
    ) -> dict[str, Any]:
        allowed, params = predicate(a)
        row = await one(
            s,
            "SELECT "
            + ",".join("s." + f for f in SERVER_FIELDS.split(","))
            + " FROM inventory.servers s WHERE s.id=:sid AND "
            + allowed
            + (" FOR UPDATE" if lock else ""),
            sid=sid,
            **params,
        )
        if row is None or (row["status"] == "archived" and not a.administrator):
            raise Denied(404)
        return row

    async def group(
        self, s: AsyncSession, a: Principal, gid: UUID, *, lock: bool = False
    ) -> dict[str, Any]:
        from cve_api.groups.personal import own_group

        return await own_group(s, a, gid)

    async def register(self, cookie: str | None, csrf: str, body: ServerCreate) -> dict[str, Any]:
        async with self.operation(cookie, csrf, "server:create", mutation=True) as (s, a):
            digest = hashlib.sha256(body.model_dump_json().encode()).hexdigest()
            old = await one(
                s,
                "SELECT server_id,request_digest FROM inventory.administration_req"
                "uests WHERE actor_id=:a AND request_id=:r",
                a=a.user_id,
                r=body.request_id,
            )
            if old:
                if old["request_digest"] != digest:
                    raise Denied(409, "idempotency_conflict")
                return await self.server(s, a, old["server_id"])
            params = body.model_dump(exclude={"request_id"})
            row = await one(
                s,
                "INSERT INTO inventory.servers(display_name,description,environmen"
                "t,criticality,exposure,created_by,updated_by,display_order) "
                "SELECT :display_name,:description,:environment,:criticality,:expo"
                "sure,:actor,:actor,coalesce(max(display_order),-1)+1 "
                "FROM inventory.servers RETURNING " + SERVER_FIELDS,
                **params,
                actor=a.user_id,
            )
            assert row is not None
            await execute(
                s,
                "INSERT INTO inventory.administration_requests(actor_id,request_id"
                ",request_digest,server_id) VALUES(:a,:r,:d,:s)",
                a=a.user_id,
                r=body.request_id,
                d=digest,
                s=row["id"],
            )
            await execute(
                s,
                "SELECT inventory.grant_server_owner(:server,:user)",
                user=a.user_id,
                server=row["id"],
            )
            await bump(s, "servers")
            await record(s, "server_registered", a.user_id, row["id"], {"version": row["version"]})
            return row

    async def patch(
        self,
        cookie: str | None,
        csrf: str,
        kind: Literal["server"],
        identifier: UUID,
        body: ServerPatch,
        match: str | None,
    ) -> dict[str, Any]:
        async with self.operation(
            cookie, csrf, kind + ":update", mutation=True, target=identifier
        ) as (s, a):
            old = await self.server(s, a, identifier, lock=True)
            if not a.administrator:
                owner = await one(
                    s, "SELECT created_by FROM inventory.servers WHERE id=:id", id=identifier
                )
                if not owner or owner["created_by"] != a.user_id:
                    raise Denied(404)
            check(old["version"], match)
            if old["status"] != "active":
                raise Denied(409, "archived_object")
            changes = body.model_dump(exclude_unset=True)
            table = "inventory.servers"
            fields = SERVER_FIELDS
            # Column names originate solely in the explicit Pydantic allowlist.
            row = await one(
                s,
                "UPDATE "
                + table
                + " SET "
                + ",".join(k + "=:" + k for k in changes)
                + ",version=version+1,updated_by=:actor WHERE id=:id RETURNING "
                + fields,
                **changes,
                actor=a.user_id,
                id=identifier,
            )
            assert row is not None
            await record(
                s,
                kind + "_updated",
                a.user_id,
                identifier,
                {"fields": sorted(changes), "version": row["version"]},
            )
            return row

    async def lifecycle(
        self,
        cookie: str | None,
        csrf: str,
        kind: Literal["server"],
        identifier: UUID,
        restore: bool,
        body: Lifecycle,
        match: str | None,
    ) -> dict[str, Any]:
        permission = "server:restore" if restore else "server:delete"
        async with self.operation(cookie, csrf, permission, mutation=True, target=identifier) as (
            s,
            a,
        ):
            old = await self.server(s, a, identifier, lock=True)
            check(old["version"], match)
            if (old["status"] == "archived") != restore:
                raise Denied(409, "invalid_transition")
            table = "inventory.servers"
            fields = SERVER_FIELDS
            position = "display_order"
            order = (
                (
                    ", "
                    + position
                    + "=(SELECT coalesce(max("
                    + position
                    + "),-1)+1 FROM "
                    + table
                    + ")"
                )
                if restore
                else ""
            )
            row = await one(
                s,
                "UPDATE "
                + table
                + " SET status=:status,archived_at="
                + ("NULL" if restore else "clock_timestamp()")
                + ",updated_by=:actor,version=version+1"
                + order
                + " WHERE id=:id RETURNING "
                + fields,
                status="active" if restore else "archived",
                actor=a.user_id,
                id=identifier,
            )
            assert row is not None
            await bump(s, "servers")
            await record(
                s,
                kind + ("_restored" if restore else "_archived"),
                a.user_id,
                identifier,
                {
                    "version": row["version"],
                    "previous_position": old[position],
                    "reason_digest": "sha256:" + hashlib.sha256(body.reason.encode()).hexdigest(),
                },
            )
            return row

    async def order(
        self,
        cookie: str | None,
        csrf: str | None,
        scope: str,
        body: Ordering | None = None,
        match: str | None = None,
    ) -> dict[str, Any]:
        if scope != "servers":
            raise Denied(422)
        async with self.operation(cookie, csrf, "server:reorder", mutation=body is not None) as (
            s,
            a,
        ):
            current = await rows(
                s,
                "SELECT id,display_order AS position FROM inventory.servers "
                "WHERE status='active' ORDER BY display_order,id",
            )
            ver = await revision(s, scope)
            if body is None:
                return {
                    "scope": scope,
                    "version": ver,
                    "items": current[:100],
                    "total": len(current),
                    "limit": 100,
                }
            check(ver, match)
            ids = [r["id"] for r in current]
            if body.ids is not None:
                if set(body.ids) != set(ids):
                    raise Denied(409, "incomplete_order")
                new = body.ids
            else:
                if body.move_id not in ids or (
                    body.before_id is not None and body.before_id not in ids
                ):
                    raise Denied(404)
                new = [i for i in ids if i != body.move_id]
                assert body.move_id is not None
                new.insert(new.index(body.before_id) if body.before_id else len(new), body.move_id)
            archived = await one(
                s,
                "SELECT coalesce(max(display_order),-1)+1 AS start FROM inventory.servers "
                "WHERE status<>'active'",
            )
            assert archived is not None
            start = int(archived["start"])
            # One bounded SQL statement; PostgreSQL ordinality performs bulk renumbering.
            params = {"ids": new, "start": start, "actor": a.user_id}
            sql = (
                "UPDATE inventory.servers s SET display_order=:start+x.n-1,version"
                "=version+1,updated_by=:actor FROM unnest(CAST(:ids AS uuid[])) "
                "WITH ORDINALITY x(id,n) WHERE s.id=x.id"
            )
            await execute(s, sql, **params)
            ver = await bump(s, scope)
            await record(
                s,
                "servers_reordered",
                a.user_id,
                None,
                {
                    "scope": scope,
                    "version": ver,
                    "count": len(new),
                    "order_digest": "sha256:"
                    + hashlib.sha256(json.dumps([str(i) for i in new]).encode()).hexdigest(),
                    "move_id": body.move_id,
                    "before_id": body.before_id,
                },
            )
            return {"scope": scope, "version": ver, "ids": new[:100], "total": len(new)}

    async def get(
        self, cookie: str | None, kind: Literal["server"], identifier: UUID
    ) -> dict[str, Any]:
        async with self.operation(cookie, None, kind + ":read", target=identifier) as (s, a):
            return await self.server(s, a, identifier)

    async def list_servers(
        self,
        cookie: str | None,
        *,
        search: str = "",
        limit: int = 50,
        offset: int = 0,
        group_id: UUID | None = None,
        environment: str | None = None,
        criticality: str | None = None,
        exposure: str | None = None,
        status: str = "active",
        sort: str = "manual",
    ) -> dict[str, Any]:
        if (
            len(search) > 128
            or not 1 <= limit <= 100
            or not 0 <= offset <= 100000
            or status not in {"active", "archived"}
            or sort not in {"manual", "name", "created"}
        ):
            raise Denied(422)
        async with self.operation(cookie, None, "server:read") as (s, a):
            if status == "archived" and not a.administrator:
                raise Denied()
            if group_id:
                await self.group(s, a, group_id)
            allowed, params = predicate(a)
            params.update(
                search=search,
                limit=limit,
                offset=offset,
                group=group_id,
                environment=environment,
                criticality=criticality,
                exposure=exposure,
                status=status,
            )
            where = (
                "s.status=:status AND "
                + allowed
                + " AND strpos(lower(s.display_name),lower(:search))>0"
            )
            for column in ["environment", "criticality", "exposure"]:
                if params[column] is not None:
                    where += " AND s." + column + "=:" + column
            if group_id:
                where += (
                    " AND EXISTS(SELECT 1 FROM inventory.server_group_memberships m WH"
                    "ERE m.server_id=s.id AND m.group_id=:group)"
                )
            ordering = {
                "manual": ("m.display_order" if group_id else "s.display_order"),
                "name": "lower(s.display_name)",
                "created": "s.created_at",
            }[sort]
            join = (
                " JOIN inventory.server_group_memberships m ON m.server_id=s.id AN"
                "D m.group_id=:group"
                if group_id
                else ""
            )
            found = await rows(
                s,
                "SELECT "
                + ",".join("s." + f for f in SERVER_FIELDS.split(","))
                + " FROM inventory.servers s"
                + join
                + " WHERE "
                + where
                + " ORDER BY "
                + ordering
                + ",s.id LIMIT :limit OFFSET :offset",
                **params,
            )
            total = await one(
                s, "SELECT count(*) AS n FROM inventory.servers s WHERE " + where, **params
            )
            assert total is not None
            return {"items": found, "total": total["n"], "limit": limit, "offset": offset}
