"Fresh RBAC/ACL validation in every transaction, before pagination and mutations."

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID, uuid4

from cve_common.database.queries import rows
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.administration.versioning import expected
from cve_api.auth.service import AuthService
from cve_api.auth.transactions import security_transaction
from cve_api.authorization.administration import Administration
from cve_api.authorization.engine import function_decision
from cve_api.authorization.errors import Denied
from cve_api.authorization.object_access import predicate
from cve_api.authorization.permissions import CATALOG
from cve_api.authorization.principal import Principal, load_principal
from cve_api.findings.software import attach_software

FIELDS = {
    "id",
    "server_id",
    "cve_id",
    "current_episode_id",
    "first_seen_at",
    "last_confirmed_at",
    "last_evaluated_at",
    "resolved_at",
    "closed_at",
    "latest_matching_result_id",
    "latest_matching_status",
    "matching_version",
    "current_priority",
    "review_state",
    "assignee_user_id",
    "version",
    "server_status",
    "server_name",
    "primary_group_id",
    "captured_at",
    "matched_at",
    "technical_is_current",
    "evidence_age_hours",
    "due_at",
    "is_overdue",
    "has_active_exception",
    "assignee_is_eligible",
    "is_stale",
}
SORTS = {
    "priority": (
        "CASE f.current_priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' TH"
        "EN 2 WHEN 'low' THEN 3 ELSE 4 END"
    ),
    "first_detected": "f.first_seen_at",
    "last_evaluated": "f.last_evaluated_at",
    "deadline": "f.due_at",
    "server": "s.display_name",
    "cve": "f.cve_id",
}


def project(row: dict[str, Any]) -> dict[str, Any]:
    result = {k: v for k, v in row.items() if k in FIELDS}
    result["affected_software"] = row.get("affected_software", [])
    result["lifecycle_status"] = row["status"]
    result["first_detected_at"] = row["first_seen_at"]
    basis = row.get("priority_basis") or {}
    result.update(
        cvss=basis.get("cvss"),
        kev_status=basis.get("kev_status", "unknown"),
        kev_is_current=basis.get("kev_is_current", False),
        epss=basis.get("epss"),
        kev_due_date=basis.get("kev_due_date"),
    )
    return result


class Findings:
    def __init__(self, auth: AuthService) -> None:
        self.auth = auth

    @asynccontextmanager
    async def operation(
        self, cookie: str | None, csrf: str | None, action: str, *, target: UUID | None = None
    ) -> AsyncIterator[tuple[AsyncSession, Principal]]:
        try:
            async with security_transaction(self.auth.database, mutation=False) as s:
                principal, current = await load_principal(self.auth, s, cookie, csrf)
                if not function_decision(principal, action).allow:
                    raise Denied()
                if CATALOG[action].reauthentication and csrf is not None:
                    await self.auth.consume_reauth(s, current)
                yield s, principal
        except Denied:
            await Administration(self.auth).log_denial(cookie, "finding_action_denied", target)
            raise
        except DBAPIError as error:
            state = getattr(error.orig, "sqlstate", None)
            status = {
                "40001": 412,
                "42501": 403,
                "P0002": 404,
                "23514": 409,
                "23505": 409,
                "22023": 422,
                "22P02": 422,
                "23502": 422,
            }.get(str(state))
            if status:
                await Administration(self.auth).log_denial(cookie, "finding_action_denied", target)
                raise Denied(status) from None
            raise

    async def visible(
        self, s: AsyncSession, actor: Principal, identity: UUID, action: str = "finding:read"
    ) -> dict[str, Any]:
        allowed, params = predicate(actor, action)
        values = await rows(
            s,
            (
                "SELECT f.* FROM findings.current_findings f JOIN inventory.servers s ON s."
                "id=f.server_id WHERE f.id=:id AND "
            )
            + allowed,
            id=identity,
            **params,
        )
        if not values:
            raise Denied(404)
        return values[0]

    async def list(
        self, cookie: str | None, filters: dict[str, Any], *, summary: bool = False
    ) -> dict[str, Any]:
        async with self.operation(cookie, None, "finding:read") as (s, actor):
            allowed, params = predicate(actor, "finding:read")
            params["group_owner"] = actor.user_id
            clauses = [allowed]
            if filters.get("archived") is None:
                clauses.append("s.status='active'")
            definitions = {
                "matching_status": (
                    "(f.latest_matching_status=:matching_status OR (:matching_status='affected' "
                    "AND f.latest_matching_status='potentially_affected'))"
                ),
                "server_id": "f.server_id=:server_id",
                "group_id": (
                    "EXISTS(SELECT 1 FROM inventory.server_group_memberships m JOIN "
                    "inventory.server_groups g ON g.id=m.group_id WHERE m.server_id=s.id AND "
                    "m.group_id=:group_id AND g.owner_id=:group_owner)"
                ),
                "lifecycle": "f.status=:lifecycle",
                "priority": "f.current_priority=:priority",
                "cve_id": "f.cve_id=:cve_id",
                "overdue": "f.is_overdue=:overdue",
                "stale": "f.is_stale=:stale",
                "assigned": "(f.assignee_user_id IS NOT NULL)=:assigned",
                "assignee": "f.assignee_user_id=:assignee",
                "exception": "f.has_active_exception=:exception",
                "kev": (
                    "(f.priority_basis->>'kev_status'='present' AND (f.priority_basis->>'ke"
                    "v_is_current')::boolean)=:kev"
                ),
                "archived": "(s.status='archived')=:archived",
            }
            for key, sql in definitions.items():
                if filters.get(key) is not None:
                    clauses.append(sql)
                    params[key] = filters[key]
            where = " AND ".join(clauses)
            base = (
                " FROM findings.current_findings f JOIN inventory.servers s ON s.id=f.s"
                "erver_id WHERE "
            ) + where
            if summary:
                values = await rows(
                    s,
                    "SELECT f.status AS lifecycle,f.current_priority AS priority,count(*) AS count"
                    + base
                    + " GROUP BY f.status,f.current_priority ORDER BY f.status,f.current_priority",
                    **params,
                )
                return {"items": values, "total": sum(r["count"] for r in values)}
            limit, offset = filters["limit"], filters["offset"]
            order = (
                SORTS[filters["sort"]]
                + (" DESC" if filters["direction"] == "desc" else " ASC")
                + " NULLS LAST,f.id"
            )
            values = await rows(
                s,
                "SELECT f.*" + base + " ORDER BY " + order + " LIMIT :limit OFFSET :offset",
                limit=limit,
                offset=offset,
                **params,
            )
            total = (await s.execute(text("SELECT count(*)" + base), params)).scalar_one()
            await attach_software(s, values)
            return {
                "items": [project(r) for r in values],
                "total": total,
                "limit": limit,
                "offset": offset,
            }

    async def detail(self, cookie: str | None, identity: UUID) -> dict[str, Any]:
        async with self.operation(cookie, None, "finding:read", target=identity) as (s, actor):
            finding = await self.visible(s, actor, identity)
            await attach_software(s, [finding])
            return project(finding)

    async def related(
        self,
        cookie: str | None,
        identity: UUID,
        section: str,
        limit: int,
        offset: int,
        result_id: UUID | None = None,
    ) -> dict[str, Any]:
        async with self.operation(cookie, None, "finding:read", target=identity) as (s, actor):
            f = await self.visible(s, actor, identity)
            params: dict[str, Any] = {"id": identity, "limit": limit, "offset": offset}
            queries = {
                "history": (
                    "SELECT id,episode_id,finding_version,kind,reason,actor_user_id,actor_r"
                    "ole,old_value,new_value,occurred_at FROM findings.audit_events WHERE f"
                    "inding_id=:id ORDER BY occurred_at DESC,id DESC"
                ),
                "episodes": (
                    "SELECT e.*,c.closed_at,c.closure_kind,CASE WHEN c.closure_kind='techni"
                    "cal_fix' THEN c.result_id END AS resolution_result_id,c.result_id AS c"
                    "losure_basis_result_id,c.policy_id AS resolution_policy_id FROM findin"
                    "gs.episodes e LEFT JOIN findings.episode_closures c ON c.episode_id=e."
                    "id WHERE e.finding_id=:id ORDER BY e.number DESC"
                ),
                "exceptions": (
                    "SELECT * FROM findings.exception_state WHERE finding_id=:id ORDER BY c"
                    "reated_at DESC,id DESC"
                ),
                "notes": (
                    "SELECT * FROM findings.notes WHERE finding_id=:id ORDER BY created_at "
                    "DESC,id DESC"
                ),
                "reviews": (
                    "SELECT * FROM findings.reviews WHERE finding_id=:id ORDER BY created_a"
                    "t DESC,id DESC"
                ),
                "mitigations": (
                    "SELECT * FROM findings.mitigations WHERE finding_id=:id ORDER BY creat"
                    "ed_at DESC,id DESC"
                ),
                "assignments": (
                    "SELECT * FROM findings.assignments WHERE finding_id=:id ORDER BY creat"
                    "ed_at DESC,id DESC"
                ),
                "priority": (
                    "SELECT id,finding_id,episode_id,priority,policy_id,signals,reasons,"
                    "encode(fingerprint,'hex') AS input_fingerprint,created_at "
                    "FROM findings.priority_history WHERE finding_id=:id "
                    "ORDER BY created_at DESC,id DESC"
                ),
                "deadlines": (
                    "SELECT * FROM findings.deadlines WHERE finding_id=:id ORDER BY created"
                    "_at DESC,id DESC"
                ),
            }
            if section == "evidence":
                selected = result_id or f["latest_matching_result_id"]
                exists = await rows(
                    s,
                    (
                        "SELECT 1 FROM findings.match_observations WHERE finding_id=:id AND"
                        " result_id=:result"
                    ),
                    id=identity,
                    result=selected,
                )
                if not exists:
                    raise Denied(404)
                values = await rows(
                    s,
                    (
                        "SELECT position,component_id,context,package_id,decision FROM matc"
                        "hing.component_results WHERE result_id=:result ORDER BY position L"
                        "IMIT :limit OFFSET :offset"
                    ),
                    result=selected,
                    limit=limit,
                    offset=offset,
                )
                return {"result_id": selected, "items": values, "limit": limit, "offset": offset}
            return {
                "items": await rows(s, queries[section] + " LIMIT :limit OFFSET :offset", **params),
                "limit": limit,
                "offset": offset,
            }

    async def command(
        self,
        cookie: str | None,
        csrf: str,
        identity: UUID,
        action: str,
        payload: BaseModel,
        match: str | None,
        *,
        permission: str = "finding:update",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        version = expected(match)
        async with self.operation(cookie, csrf, permission, target=identity) as (s, actor):
            await self.visible(s, actor, identity, "finding:update")
            args = payload.model_dump(mode="json") | (extra or {})
            result = (
                await s.execute(
                    text(
                        "SELECT findings.command(:session,:id,:version,:action,CAST(:ar"
                        "gs AS jsonb),:correlation)"
                    ),
                    {
                        "session": actor.session_id,
                        "id": identity,
                        "version": version,
                        "action": action,
                        "args": json.dumps(args),
                        "correlation": uuid4(),
                    },
                )
            ).scalar_one()
            await attach_software(s, [result])
            return project(result)
