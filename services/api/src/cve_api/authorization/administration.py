"""Every read/mutation revalidates identity, capability, target and revision at service level."""

import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.access.schemas import ReplaceAccess
from cve_api.auth.errors import AuthError
from cve_api.auth.repository import execute, one
from cve_api.auth.service import AuthService
from cve_api.auth.transactions import security_transaction
from cve_api.roles.schemas import RoleCreate, RolePatch
from cve_api.users.schemas import AssignRoles, UserCreate, UserPatch, Version

from .audit import record
from .engine import decide, function_decision
from .errors import Denied
from .last_admin import check_last_administrator
from .object_access import visible_group_counts, visible_servers
from .permissions import CATALOG, SYSTEM_ROLES
from .policies import custom_permissions, target_allowed
from .principal import Principal, load_principal

USER_FIELDS = "id,username,email,display_name,status,version,auth_version,created_at,updated_at"


class Administration:
    def __init__(self, auth: AuthService) -> None:
        self.auth = auth

    async def log_denial(self, cookie: str | None, reason: str, target: UUID | None = None) -> None:
        try:
            async with security_transaction(self.auth.database) as session:
                current = await self.auth.resolve(session, cookie)
                actor = current["user"]["id"]
            await self.auth.limits.check("authorization-denied", str(actor), 10)
            async with security_transaction(self.auth.database) as session:
                await record(
                    session,
                    "last_admin_protected" if reason == "last_admin" else "denied",
                    actor,
                    target,
                    success=False,
                    reason=reason,
                )
        except (AuthError, SQLAlchemyError):
            pass

    @asynccontextmanager
    async def operation(
        self,
        cookie: str | None,
        csrf: str | None,
        action: str,
        *,
        mutation: bool = False,
        target_id: UUID | None = None,
    ) -> AsyncIterator[tuple[AsyncSession, Principal, dict[str, Any]]]:
        try:
            async with security_transaction(self.auth.database, mutation=mutation) as session:
                actor, current = await load_principal(self.auth, session, cookie, csrf)
                if not function_decision(actor, action).allow:
                    raise Denied()
                if mutation and CATALOG[action].reauthentication:
                    await self.auth.consume_reauth(session, current)
                yield session, actor, current
                if mutation:
                    await check_last_administrator(session)
        except AuthError as error:
            if error.status == 403:
                await self.log_denial(cookie, "reauthentication_or_csrf", target_id)
            raise
        except Denied as error:
            await self.log_denial(cookie, error.reason, target_id)
            raise
        except IntegrityError as error:
            constraint = getattr(getattr(error.orig, "diag", None), "constraint_name", None)
            reason = (
                "last_admin"
                if constraint == "usable_administrator_required"
                else "conflicting_state"
            )
            await self.log_denial(cookie, reason, target_id)
            raise Denied(409, reason) from None

    async def user_list(
        self, cookie: str | None, search: str = "", limit: int = 50, offset: int = 0
    ) -> dict[str, Any]:
        if len(search) > 128 or not 1 <= limit <= 100 or not 0 <= offset <= 100000:
            raise Denied(422)
        async with self.operation(cookie, None, "user:list") as (s, a, _):
            where = "strpos(lower(u.username||' '||u.display_name),lower(:search))>0"
            if not a.administrator:
                where += (
                    " AND NOT EXISTS(SELECT 1 FROM security.user_roles ur JO"
                    "IN security.roles r ON r.id=ur.role_id WHERE ur.user_id"
                    "=u.id AND r.code IN ('admin','user_admin'))"
                )
            params = {"search": search, "limit": limit, "offset": offset}
            fields = ",".join("u." + c for c in USER_FIELDS.split(","))
            rows = (
                (
                    await s.execute(
                        text(
                            "SELECT "
                            + fields
                            + ", ARRAY(SELECT r.code FROM security.user_roles ur "
                            "JOIN security.roles r ON r.id=ur.role_id "
                            "WHERE ur.user_id=u.id ORDER BY r.code) AS roles"
                            + " FROM security.users u WHERE "
                            + where
                            + " ORDER BY u.id LIMIT :limit OFFSET :offset"
                        ),
                        params,
                    )
                )
                .mappings()
                .all()
            )
            total = (
                await s.execute(
                    text("SELECT count(*) FROM security.users u WHERE " + where), params
                )
            ).scalar_one()
            return {
                "items": [dict(r) for r in rows],
                "total": total,
                "limit": limit,
                "offset": offset,
            }

    async def user_get(self, cookie: str | None, uid: UUID) -> dict[str, Any]:
        async with self.operation(cookie, None, "user:read", target_id=uid) as (s, a, _):
            await target_allowed(s, a, uid)
            row = await one(
                s, "SELECT " + USER_FIELDS + " FROM security.users WHERE id=:id", id=uid
            )
            assert row is not None
            return row

    async def user_create(self, cookie: str | None, csrf: str, body: UserCreate) -> dict[str, Any]:
        async with self.operation(cookie, csrf, "user:create", mutation=True) as (s, a, _):
            row = await one(
                s,
                (
                    "INSERT INTO security.users(username,email,display_name,"
                    "created_by) VALUES(:name,:email,:display,:actor) RETURN"
                    "ING "
                )
                + USER_FIELDS,
                name=body.username,
                email=body.email,
                display=body.display_name,
                actor=a.user_id,
            )
            assert row is not None
            await execute(
                s,
                "INSERT INTO security.user_roles(user_id,role_id,granted_by) "
                "SELECT :user,id,:actor FROM security.roles WHERE code='user'",
                user=row["id"],
                actor=a.user_id,
            )
            await record(s, "user_created", a.user_id, row["id"])
            return row

    async def user_patch(
        self, cookie: str | None, csrf: str, uid: UUID, body: UserPatch
    ) -> dict[str, Any]:
        async with self.operation(cookie, csrf, "user:update", mutation=True, target_id=uid) as (
            s,
            a,
            _,
        ):
            target = await target_allowed(s, a, uid)
            if target["version"] != body.version:
                raise Denied(409, "stale_version")
            if body.email is None and body.display_name is None:
                raise Denied(422)
            row = await one(
                s,
                (
                    "UPDATE security.users SET display_name=coalesce(:displa"
                    "y,display_name),email=coalesce(:email,email),version=ve"
                    "rsion+1 WHERE id=:id RETURNING "
                )
                + USER_FIELDS,
                display=body.display_name,
                email=body.email,
                id=uid,
            )
            assert row is not None
            await record(
                s,
                "user_updated",
                a.user_id,
                uid,
                details={
                    "version": body.version + 1,
                    "fields": sorted(body.model_fields_set & {"email", "display_name"}),
                    "reason_digest": "sha256:" + hashlib.sha256(body.reason.encode()).hexdigest(),
                },
            )
            return row

    async def lifecycle(
        self, cookie: str | None, csrf: str, uid: UUID, action: str, body: Version
    ) -> dict[str, Any]:
        codes = {
            "enable": ("user:enable", "active", "user_enabled"),
            "disable": ("user:disable", "disabled", "user_disabled"),
            "archive": ("user:archive", "archived", "user_archived"),
            "lock": ("user:disable", "locked", "user_locked"),
            "revoke-sessions": ("user:session:revoke", None, "sessions_revoked"),
        }
        if action not in codes:
            raise Denied(404)
        permission, status, event = codes[action]
        async with self.operation(cookie, csrf, permission, mutation=True, target_id=uid) as (
            s,
            a,
            _,
        ):
            target = await target_allowed(s, a, uid)
            if target["version"] != body.version:
                raise Denied(409, "stale_version")
            if target["status"] == "archived":
                raise Denied(409, "archived_account")
            if status == "active":
                credential = await one(
                    s,
                    (
                        "SELECT user_id FROM security.password_credentials WHERE"
                        " user_id=:u AND revoked_at IS NULL"
                    ),
                    u=uid,
                )
                if credential is None or target["status"] == "pending_activation":
                    raise Denied(409, "activation_required")
            if not a.administrator and action == "lock":
                raise Denied()
            await execute(
                s,
                (
                    "UPDATE security.users SET status=coalesce(:status,statu"
                    "s),archived_at=CASE WHEN :status='archived' THEN clock_"
                    "timestamp() ELSE archived_at END,auth_version=auth_vers"
                    "ion+1,version=version+1 WHERE id=:u"
                ),
                status=status,
                u=uid,
            )
            await record(
                s,
                event,
                a.user_id,
                uid,
                details={
                    "version": body.version + 1,
                    "previous_status": target["status"],
                    "status": status or target["status"],
                    "reason_digest": "sha256:" + hashlib.sha256(body.reason.encode()).hexdigest(),
                },
            )
            row = await one(
                s, "SELECT " + USER_FIELDS + " FROM security.users WHERE id=:id", id=uid
            )
            assert row is not None
            return row

    async def role_list(
        self, cookie: str | None, role_id: UUID | None = None
    ) -> list[dict[str, Any]]:
        async with self.operation(cookie, None, "role:list") as (s, _a, _):
            rows = (
                (
                    await s.execute(
                        text(
                            "SELECT r.id,r.code,r.name,r.description,r.is_system,r.v"
                            "ersion,coalesce(array_agg(p.permission_code) FILTER(WHE"
                            "RE p.permission_code IS NOT NULL),'{}') AS permissions "
                            "FROM security.roles r LEFT JOIN security.role_permissio"
                            "ns p ON p.role_id=r.id WHERE CAST(:id AS uuid) IS NULL "
                            "OR r.id=:id GROUP BY r.id ORDER BY r.code LIMIT 100"
                        ),
                        {"id": role_id},
                    )
                )
                .mappings()
                .all()
            )
            if role_id and not rows:
                raise Denied(404, "unknown_role")
            return [dict(r) for r in rows]

    async def role_save(
        self,
        cookie: str | None,
        csrf: str,
        body: RoleCreate | RolePatch,
        role_id: UUID | None = None,
    ) -> dict[str, Any]:
        custom_permissions(body.permissions)
        action = "role:update" if role_id else "role:create"
        async with self.operation(cookie, csrf, action, mutation=True, target_id=role_id) as (
            s,
            a,
            _,
        ):
            if not a.administrator:
                raise Denied()
            if role_id:
                existing = await one(
                    s, "SELECT * FROM security.roles WHERE id=:id FOR UPDATE", id=role_id
                )
                if existing is None:
                    raise Denied(404)
                if existing["is_system"]:
                    raise Denied(403, "system_role")
                assert isinstance(body, RolePatch)
                if existing["version"] != body.version:
                    raise Denied(409, "stale_version")
                await execute(
                    s,
                    (
                        "UPDATE security.roles SET name=:name,description=:descr"
                        "iption,version=version+1 WHERE id=:id"
                    ),
                    name=body.name,
                    description=body.description,
                    id=role_id,
                )
                await execute(
                    s, ("DELETE FROM security.role_permissions WHERE role_id=:id"), id=role_id
                )
                await execute(
                    s,
                    (
                        "UPDATE security.users SET auth_version=auth_version+1,v"
                        "ersion=version+1 WHERE id IN(SELECT user_id FROM securi"
                        "ty.user_roles WHERE role_id=:id)"
                    ),
                    id=role_id,
                )
            else:
                assert isinstance(body, RoleCreate)
                if body.code in SYSTEM_ROLES:
                    raise Denied(403, "system_role")
                row = await one(
                    s,
                    (
                        "INSERT INTO security.roles(code,name,description,create"
                        "d_by) VALUES(:code,:name,:description,:actor) RETURNING"
                        " id"
                    ),
                    code=body.code,
                    name=body.name,
                    description=body.description,
                    actor=a.user_id,
                )
                assert row is not None
                role_id = row["id"]
            for code in sorted(set(body.permissions)):
                await execute(
                    s,
                    (
                        "INSERT INTO security.role_permissions(role_id,permissio"
                        "n_code) VALUES(:id,:p)"
                    ),
                    id=role_id,
                    p=code,
                )
            await record(
                s,
                "role_updated" if action == "role:update" else "role_created",
                a.user_id,
                role_id,
                details={
                    "permission_codes": sorted(body.permissions),
                    "version": body.version + 1 if isinstance(body, RolePatch) else 1,
                },
            )
            row = await one(
                s,
                (
                    "SELECT id,code,name,description,is_system,version FROM "
                    "security.roles WHERE id=:id"
                ),
                id=role_id,
            )
            assert row is not None
            row["permissions"] = sorted(body.permissions)
            return row

    async def role_delete(
        self, cookie: str | None, csrf: str, role_id: UUID, body: Version
    ) -> None:
        async with self.operation(
            cookie, csrf, "role:delete", mutation=True, target_id=role_id
        ) as (s, a, _):
            role = await one(s, "SELECT * FROM security.roles WHERE id=:id FOR UPDATE", id=role_id)
            if not role:
                raise Denied(404)
            if role["is_system"]:
                raise Denied(403, "system_role")
            if role["version"] != body.version:
                raise Denied(409, "stale_version")
            await execute(
                s,
                (
                    "UPDATE security.users SET auth_version=auth_version+1,v"
                    "ersion=version+1 WHERE id IN(SELECT user_id FROM securi"
                    "ty.user_roles WHERE role_id=:id)"
                ),
                id=role_id,
            )
            await execute(s, "DELETE FROM security.user_roles WHERE role_id=:id", id=role_id)
            await execute(s, "DELETE FROM security.role_permissions WHERE role_id=:id", id=role_id)
            await execute(s, "DELETE FROM security.roles WHERE id=:id", id=role_id)
            await record(
                s,
                "role_deleted",
                a.user_id,
                role_id,
                details={"code": role["code"], "version": role["version"]},
            )

    async def assign_roles(
        self, cookie: str | None, csrf: str, uid: UUID, body: AssignRoles
    ) -> dict[str, Any]:
        async with self.operation(
            cookie, csrf, "user:role:assign", mutation=True, target_id=uid
        ) as (s, a, _):
            target = await target_allowed(s, a, uid)
            if target["version"] != body.version:
                raise Denied(409, "stale_version")
            if len(body.role_ids) != len(set(body.role_ids)):
                raise Denied(422)
            role_ids = list(body.role_ids)
            admin_role = await one(s, "SELECT id FROM security.roles WHERE code='admin'")
            if admin_role and admin_role["id"] in role_ids:
                base_role = await one(s, "SELECT id FROM security.roles WHERE code='user'")
                if base_role and base_role["id"] not in role_ids:
                    role_ids.append(base_role["id"])
            old = {
                r[0]
                for r in (
                    await s.execute(
                        text("SELECT role_id FROM security.user_roles WHERE user_id=:u"), {"u": uid}
                    )
                ).all()
            }
            roles = (
                (
                    await s.execute(
                        text("SELECT id,code,is_system FROM security.roles WHERE id=ANY(:ids)"),
                        {"ids": role_ids},
                    )
                )
                .mappings()
                .all()
            )
            if len(roles) != len(role_ids):
                raise Denied(422, "unknown_role")
            if uid == a.user_id and not set(role_ids) <= old:
                raise Denied(403, "self_escalation")
            if not a.administrator and any(
                r["code"] not in {"user", "viewer", "security_analyst"} for r in roles
            ):
                raise Denied(403, "protected_role")
            if (
                any(r["code"] in {"admin", "user_admin"} for r in roles)
                and not function_decision(a, "role:assign:privileged").allow
            ):
                raise Denied()
            await execute(s, "DELETE FROM security.user_roles WHERE user_id=:u", u=uid)
            for role in roles:
                await execute(
                    s,
                    (
                        "INSERT INTO security.user_roles(user_id,role_id,granted"
                        "_by) VALUES(:u,:r,:a) ON CONFLICT(user_id,role_id) DO NOTHING"
                    ),
                    u=uid,
                    r=role["id"],
                    a=a.user_id,
                )
            await execute(
                s,
                (
                    "UPDATE security.users SET auth_version=auth_version+1,v"
                    "ersion=version+1 WHERE id=:u"
                ),
                u=uid,
            )
            await record(
                s,
                "roles_assigned",
                a.user_id,
                uid,
                details={
                    "role_ids": role_ids,
                    "removed_role_ids": sorted(old - set(role_ids)),
                    "user_version": body.version + 1,
                },
            )
            if old - set(role_ids):
                await record(
                    s,
                    "roles_revoked",
                    a.user_id,
                    uid,
                    details={"removed_role_ids": sorted(old - set(role_ids))},
                )
            return {"user_id": uid, "role_ids": role_ids, "version": body.version + 1}

    async def access_get(self, cookie: str | None, server_id: UUID) -> dict[str, Any]:
        async with self.operation(cookie, None, "server:acl:manage", target_id=server_id) as (
            s,
            _a,
            _,
        ):
            if not await one(s, "SELECT id FROM inventory.servers WHERE id=:s", s=server_id):
                raise Denied(404)
            count = await one(
                s,
                ("SELECT count(*) AS n FROM security.user_server_access WHERE server_id=:s"),
                s=server_id,
            )
            if count and count["n"] > 100:
                raise Denied(409, "operator_acl_review_required")
            revision = await one(
                s,
                ("SELECT version FROM security.server_acl_versions WHERE server_id=:s"),
                s=server_id,
            )
            rows = (
                (
                    await s.execute(
                        text(
                            "SELECT id,user_id,can_read,can_upload,findings_read,fin"
                            "dings_manage,version,created_at,updated_at,granted_by F"
                            "ROM security.user_server_access WHERE server_id=:s ORDE"
                            "R BY user_id"
                        ),
                        {"s": server_id},
                    )
                )
                .mappings()
                .all()
            )
            return {
                "server_id": server_id,
                "version": revision["version"] if revision else 0,
                "grants": [dict(r) for r in rows],
            }

    async def access_replace(
        self, cookie: str | None, csrf: str, server_id: UUID, body: ReplaceAccess
    ) -> dict[str, Any]:
        async with self.operation(
            cookie, csrf, "server:acl:manage", mutation=True, target_id=server_id
        ) as (s, a, _):
            if not a.administrator:
                raise Denied()
            if not await one(s, "SELECT id FROM inventory.servers WHERE id=:s", s=server_id):
                raise Denied(404)
            if len({g.user_id for g in body.grants}) != len(body.grants):
                raise Denied(422)
            if any(g.user_id == a.user_id for g in body.grants):
                raise Denied(403, "self_escalation")
            await execute(
                s,
                (
                    "INSERT INTO security.server_acl_versions(server_id) VAL"
                    "UES(:s) ON CONFLICT DO NOTHING"
                ),
                s=server_id,
            )
            old = await one(
                s,
                ("SELECT version FROM security.server_acl_versions WHERE server_id=:s FOR UPDATE"),
                s=server_id,
            )
            if old is None or old["version"] != body.version:
                raise Denied(409, "stale_version")
            count = await one(
                s,
                ("SELECT count(*) AS n FROM security.user_server_access WHERE server_id=:s"),
                s=server_id,
            )
            if count and count["n"] > 100:
                raise Denied(409, "operator_acl_review_required")
            affected = {
                r[0]
                for r in (
                    await s.execute(
                        text("SELECT user_id FROM security.user_server_access WHERE server_id=:s"),
                        {"s": server_id},
                    )
                ).all()
            }
            await execute(
                s, ("DELETE FROM security.user_server_access WHERE server_id=:s"), s=server_id
            )
            for grant in body.grants:
                rights = set(grant.rights)
                if (
                    len(rights) != len(grant.rights)
                    or ("view" not in rights)
                    or ("findings_manage" in rights and "findings_read" not in rights)
                ):
                    raise Denied(422, "invalid_acl")
                if not await one(
                    s,
                    ("SELECT id FROM security.users WHERE id=:u AND status<>'archived'"),
                    u=grant.user_id,
                ):
                    raise Denied(422, "unknown_grantee")
                await execute(
                    s,
                    (
                        "INSERT INTO security.user_server_access(user_id,server_"
                        "id,can_read,can_upload,findings_read,findings_manage,gr"
                        "anted_by,version) VALUES(:u,:s,true,:upload,:read,:mana"
                        "ge,:a,:v)"
                    ),
                    u=grant.user_id,
                    s=server_id,
                    upload="inventory_upload" in rights,
                    read="findings_read" in rights,
                    manage="findings_manage" in rights,
                    a=a.user_id,
                    v=body.version + 1,
                )
                affected.add(grant.user_id)
            if affected:
                await execute(
                    s,
                    (
                        "UPDATE security.users SET auth_version=auth_version+1,v"
                        "ersion=version+1 WHERE id=ANY(:ids)"
                    ),
                    ids=sorted(affected),
                )
            await execute(
                s,
                (
                    "UPDATE security.server_acl_versions SET version=version"
                    "+1,updated_at=clock_timestamp() WHERE server_id=:s"
                ),
                s=server_id,
            )
            await record(
                s,
                "acl_revoked",
                a.user_id,
                server_id,
                details={
                    "set_version": body.version + 1,
                    "affected_users": sorted(affected),
                    "grants": [g.model_dump(mode="json") for g in body.grants],
                },
            )
            if body.grants:
                await record(
                    s,
                    "acl_granted",
                    a.user_id,
                    server_id,
                    details={
                        "set_version": body.version + 1,
                        "grants": [g.model_dump(mode="json") for g in body.grants],
                    },
                )
            return {"server_id": server_id, "version": body.version + 1}

    async def effective(self, cookie: str | None, uid: UUID | None = None) -> dict[str, Any]:
        async with security_transaction(self.auth.database, mutation=False) as session:
            actor, _ = await load_principal(self.auth, session, cookie)
            if uid and uid != actor.user_id:
                if not function_decision(actor, "user:read").allow:
                    raise Denied()
                await target_allowed(session, actor, uid)
                row = await one(
                    session,
                    (
                        "SELECT coalesce(array_agg(DISTINCT p.code) FILTER(WHERE"
                        " p.identity_type='human'),'{}') AS permissions FROM sec"
                        "urity.user_roles ur JOIN security.role_permissions rp O"
                        "N rp.role_id=ur.role_id JOIN security.permissions p ON "
                        "p.code=rp.permission_code WHERE ur.user_id=:u"
                    ),
                    u=uid,
                )
                return {
                    "user_id": uid,
                    "permissions": sorted(set(row["permissions"]) & set(CATALOG)) if row else [],
                }
            return {
                "user_id": actor.user_id,
                "roles": sorted(actor.roles),
                "permissions": sorted(actor.permissions & set(CATALOG)),
                "authorization_version": actor.authorization_version,
            }

    async def servers(
        self, cookie: str | None, search: str = "", limit: int = 50, offset: int = 0
    ) -> dict[str, Any]:
        async with self.operation(cookie, None, "server:read") as (s, a, _):
            return await visible_servers(s, a, search=search, limit=limit, offset=offset)

    async def groups(self, cookie: str | None) -> list[dict[str, Any]]:
        async with self.operation(cookie, None, "group:read") as (s, a, _):
            return await visible_group_counts(s, a)

    async def check_object(self, cookie: str | None, action: str, server_id: UUID) -> None:
        async with self.operation(cookie, None, action, target_id=server_id) as (s, a, _):
            if not (await decide(s, a, action, server_id)).allow:
                raise Denied(404, "invisible_object")

    async def recovery_request(
        self, cookie: str | None, csrf: str, uid: UUID, body: Version
    ) -> dict[str, Any]:
        async with self.operation(
            cookie, csrf, "user:mfa:recovery", mutation=True, target_id=uid
        ) as (s, a, _):
            if not a.administrator or uid == a.user_id:
                raise Denied(403, "protected_recovery")
            target = await target_allowed(s, a, uid)
            if target["version"] != body.version:
                raise Denied(409, "stale_version")
            if target["status"] != "active":
                raise Denied(409)
            factor = await one(
                s,
                "SELECT id FROM security.mfa_methods WHERE user_id=:u "
                "AND verified_at IS NOT NULL LIMIT 1",
                u=uid,
            )
            if factor is None:
                raise Denied(409, "no_previous_mfa")
            await execute(
                s,
                (
                    "UPDATE security.recovery_requests SET revoked_at=clock_"
                    "timestamp() WHERE user_id=:u AND redeemed_at IS NULL AN"
                    "D revoked_at IS NULL"
                ),
                u=uid,
            )
            row = await one(
                s,
                (
                    "INSERT INTO security.recovery_requests(user_id,requeste"
                    "d_by,reason) VALUES(:u,:a,:r) RETURNING id,expires_at"
                ),
                u=uid,
                a=a.user_id,
                r=body.reason,
            )
            await execute(
                s,
                (
                    "UPDATE security.mfa_methods SET revoked_at=clock_timest"
                    "amp() WHERE user_id=:u AND revoked_at IS NULL"
                ),
                u=uid,
            )
            await execute(
                s,
                (
                    "UPDATE security.recovery_codes SET revoked_at=clock_tim"
                    "estamp() WHERE user_id=:u AND revoked_at IS NULL"
                ),
                u=uid,
            )
            await execute(
                s,
                (
                    "UPDATE security.users SET mfa_required=true,auth_versio"
                    "n=auth_version+1,version=version+1 WHERE id=:u"
                ),
                u=uid,
            )
            await record(
                s,
                "mfa_recovery_requested",
                a.user_id,
                uid,
                details={"request_id": row["id"] if row else None, "version": body.version + 1},
            )
            assert row is not None
            return {
                "request_id": row["id"],
                "expires_at": row["expires_at"],
                "delivery": "manual_operator_required",
                "version": body.version + 1,
            }
