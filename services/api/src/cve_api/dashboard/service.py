"Scope filtering before all counts; read-only current projections and UTC event trends."

from typing import Any
from uuid import UUID

from cve_common.database.queries import one, rows

from cve_api.administration.service import InventoryAdministration
from cve_api.authorization.engine import function_decision
from cve_api.authorization.errors import Denied
from cve_api.authorization.object_access import predicate
from cve_api.findings.service import Findings


class Dashboard(Findings):
    async def overview(self, cookie: str | None) -> dict[str, Any]:
        async with self.operation(cookie, None, "security:overview:read") as (s, actor):
            scope, params = predicate(actor, "security:overview:read")
            finder, fparams = (
                predicate(actor, "finding:read")
                if function_decision(actor, "finding:read").allow
                else ("false", {})
            )
            values = await one(
                s,
                (
                    "SELECT count(*) AS n,clock_timestamp() AS ts FROM "
                    "inventory.servers s WHERE s.status='active' AND "
                )
                + scope,
                **params,
            )
            assert values
            permitted = function_decision(actor, "finding:read").allow
            counts = await one(
                s,
                (
                    "SELECT count(*) FILTER(WHERE f.status IN ('open','"
                    "in_progress')) AS open_findings,\n              cou"
                    "nt(DISTINCT f.server_id) FILTER(WHERE f.status IN "
                    "('open','in_progress') AND f.latest_matching_statu"
                    "s='affected' AND f.technical_is_current) AS server"
                    "s_affected,\n              count(*) FILTER(WHERE f."
                    "status IN ('open','in_progress') AND f.current_pri"
                    "ority='critical') AS critical,\n              count"
                    "(*) FILTER(WHERE f.status IN ('open','in_progress'"
                    ") AND f.current_priority='high') AS high,\n        "
                    "      count(*) FILTER(WHERE f.latest_matching_stat"
                    "us='potentially_affected') AS potentially_affected"
                    ",\n              count(*) FILTER(WHERE f.latest_mat"
                    "ching_status='unknown') AS unknown,\n              "
                    "count(*) FILTER(WHERE f.is_overdue) AS overdue,\n  "
                    "            count(*) FILTER(WHERE f.priority_basis"
                    "->>'kev_status'='present' AND (f.priority_basis->>"
                    "'kev_is_current')::boolean) AS kev\n              F"
                    "ROM findings.current_findings f JOIN inventory.ser"
                    "vers s ON s.id=f.server_id\n              WHERE s.s"
                    "tatus='active' AND "
                )
                + scope
                + " AND "
                + finder,
                **params,
                **({} if "actor" in params else fparams),
            )
            assert counts
            result: dict[str, Any] = {
                "generated_at": values["ts"],
                "scope": "authorized_servers",
                "active_servers": values["n"],
                "finding_data_available": permitted,
                **{k: v if permitted else None for k, v in counts.items()},
            }
            for name, field in [
                ("priorities", "current_priority"),
                ("lifecycle", "status"),
                ("technical", "latest_matching_status"),
                ("kev_priorities", "current_priority"),
            ]:
                condition = (
                    (
                        " AND f.priority_basis->>'kev_status'='present' AND"
                        " (f.priority_basis->>'kev_is_current')::boolean"
                    )
                    if name == "kev_priorities"
                    else ""
                )
                result[name] = {
                    r["key"]: r["n"]
                    for r in await rows(
                        s,
                        "SELECT f."
                        + field
                        + (
                            " AS key,count(*) AS n FROM findings.current_findin"
                            "gs f JOIN inventory.servers s ON s.id=f.server_id "
                            "WHERE s.status='active' AND "
                        )
                        + scope
                        + " AND "
                        + finder
                        + condition
                        + " GROUP BY f."
                        + field,
                        **params,
                        **({} if "actor" in params else fparams),
                    )
                }
            inventory = function_decision(actor, "inventory:read").allow
            result["inventory_data_available"] = inventory
            inv = await one(
                s,
                f"""SELECT count(*) FILTER(WHERE snapshot_id IS NULL) AS missing,
              count(*) FILTER(WHERE inventory_freshness='stale') AS stale,
              count(*) FILTER(WHERE inventory_freshness='not_configured') AS not_configured,
              count(*) FILTER(WHERE latest_snapshot_id IS NOT NULL
                AND (collection_status<>'complete'
                OR processing_status<>'processed')) AS incomplete,
              count(*) FILTER(WHERE evaluations=0 AND {finder}) AS pending,
              count(*) FILTER(WHERE evaluations>current_evaluations
                AND {finder}) AS outdated_matching,
              count(*) FILTER(WHERE evaluations>0 AND evaluations=current_evaluations
                AND {finder}) AS current_matching
              FROM dashboard.server_security s WHERE s.status='active' AND """
                + scope,
                **params,
                **({} if "actor" in params else fparams),
            )
            assert inv
            result["inventory"] = {
                k: v if inventory else None
                for k, v in inv.items()
                if k in {"missing", "stale", "not_configured", "incomplete"}
            }
            result["matching"] = (
                {k: inv[k] for k in ["pending", "outdated_matching", "current_matching"]}
                if permitted
                else {}
            )
            return result

    async def trends(self, cookie: str | None, days: int) -> dict[str, Any]:
        async with self.operation(cookie, None, "security:overview:read") as (s, actor):
            if not function_decision(actor, "finding:read").allow:
                raise Denied()
            scope, params = predicate(actor, "security:overview:read")
            finding, fparams = predicate(actor, "finding:read")
            params.update(fparams)
            params["days"] = days
            found = await rows(
                s,
                (
                    "WITH visible AS (SELECT f.id FROM findings.finding"
                    "s f JOIN inventory.servers s ON s.id=f.server_id\n "
                    "             WHERE f.model_version=2 AND s.status="
                    "'active' AND "
                )
                + scope
                + " AND "
                + finding
                + (
                    "), events AS (\n              SELECT (a.occurred_at"
                    " AT TIME ZONE 'UTC')::date AS day,a.kind FROM find"
                    "ings.audit_events a JOIN visible v ON v.id=a.findi"
                    "ng_id\n              WHERE a.kind IN ('created','re"
                    "solved','reopened','closed') AND a.occurred_at>=da"
                    "te_trunc('day',clock_timestamp() AT TIME ZONE 'UTC"
                    "') AT TIME ZONE 'UTC'-make_interval(days=>:days-1)"
                    ")\n              SELECT d::date::text AS day,count("
                    "e.kind) FILTER(WHERE e.kind='created') AS detected"
                    ",\n              count(e.kind) FILTER(WHERE e.kind="
                    "'resolved') AS resolved,count(e.kind) FILTER(WHERE"
                    " e.kind='reopened') AS reopened,\n              cou"
                    "nt(e.kind) FILTER(WHERE e.kind='closed') AS closed"
                    " FROM generate_series((clock_timestamp() AT TIME Z"
                    "ONE 'UTC')::date-(:days-1),(clock_timestamp() AT T"
                    "IME ZONE 'UTC')::date,interval '1 day') d\n        "
                    "      LEFT JOIN events e ON e.day=d::date GROUP BY"
                    " d ORDER BY d"
                ),
                **params,
            )
            now = await one(s, "SELECT clock_timestamp() AS ts")
            assert now
            return {"generated_at": now["ts"], "timezone": "UTC", "days": days, "items": found}

    async def servers(
        self,
        cookie: str | None,
        *,
        limit: int,
        offset: int,
        search: str = "",
        group: UUID | None = None,
        status: str = "active",
        sort: str = "manual",
        distribution: str | None = None,
        identity: UUID | None = None,
    ) -> dict[str, Any]:
        async with self.operation(cookie, None, "server:read") as (s, actor):
            if group:
                await InventoryAdministration(self.auth).group(s, actor, group)
            if status == "archived" and not actor.administrator:
                raise Denied()
            allowed, params = predicate(actor, "server:read")
            params.update(
                limit=limit,
                offset=offset,
                search=search,
                group=group,
                status=status,
                distribution=distribution,
                id=identity,
            )
            where = (
                "s.status=:status AND "
                + allowed
                + " AND strpos(lower(s.display_name),lower(:search))>0"
            )
            if group:
                where += (
                    " AND EXISTS(SELECT 1 FROM inventory.server_group_m"
                    "emberships m WHERE m.server_id=s.id AND m.group_id"
                    "=:group)"
                )
            if distribution:
                where += " AND s.distribution=:distribution"
            if identity:
                where += " AND s.id=:id"
            order = {
                "manual": "s.display_order",
                "name": "lower(s.display_name)",
                "inventory": "s.captured_at DESC NULLS LAST",
            }[sort]
            if group and sort == "manual":
                order = (
                    "(SELECT display_order FROM inventory.server_group_"
                    "memberships m WHERE m.group_id=:group AND m.server"
                    "_id=s.id)"
                )
            inventory = function_decision(actor, "inventory:read").allow
            if not inventory and (distribution or sort == "inventory"):
                raise Denied()
            fscope, fparams = (
                predicate(actor, "finding:read")
                if function_decision(actor, "finding:read").allow
                else ("false", {})
            )
            params.update(fparams)
            found = await rows(
                s,
                "WITH page AS MATERIALIZED (SELECT s.id FROM dashboard.server_list_index s WHERE "
                + where
                + " ORDER BY "
                + order
                + ",s.id LIMIT :limit OFFSET :offset) SELECT s.*,meta.version,meta.created_by,("
                + fscope
                + ") AS can_findings FROM page CROSS JOIN LATERAL "
                + "(SELECT detail.* FROM dashboard.server_security detail "
                + "WHERE detail.id=page.id OFFSET 0) s "
                "JOIN inventory.servers meta ON meta.id=s.id ORDER BY " + order + ",s.id",
                **params,
            )
            total = await one(
                s,
                "SELECT count(*) AS n FROM dashboard.server_list_index s WHERE " + where,
                **params,
            )
            assert total
            if identity and not found:
                raise Denied(404)
            ids = [r["id"] for r in found]
            memberships = (
                await rows(
                    s,
                    (
                        "SELECT m.server_id,g.id,g.name,m.display_order FRO"
                        "M inventory.server_group_memberships m\n           "
                        "   JOIN inventory.server_groups g ON g.id=m.group_"
                        "id WHERE g.owner_id=:group_owner AND m.server_id=ANY(:ids) "
                        "AND g.status='activ"
                        "e' ORDER BY g.sort_order,g.id,m.display_order"
                    ),
                    ids=ids,
                    group_owner=actor.user_id,
                )
                if ids
                else []
            )
            summaries = (
                await rows(
                    s,
                    (
                        "SELECT f.server_id,count(*) FILTER(WHERE f.status "
                        "IN ('open','in_progress')) AS n,\n              min"
                        "(CASE f.current_priority WHEN 'critical' THEN 0 WH"
                        "EN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' T"
                        "HEN 3 ELSE 4 END) FILTER(WHERE f.status IN ('open'"
                        ",'in_progress')) AS level\n              FROM findi"
                        "ngs.current_findings f WHERE f.server_id=ANY(:ids)"
                        " GROUP BY f.server_id"
                    ),
                    ids=[r["id"] for r in found if r["can_findings"]],
                )
                if any(r["can_findings"] for r in found)
                else []
            )
            by_id = {r["server_id"]: r for r in summaries}
            items = []
            for r in found:
                summary = by_id.get(r["id"], {"n": 0, "level": None})
                items.append(
                    {
                        k: r[k]
                        for k in [
                            "id",
                            "display_name",
                            "status",
                            "primary_group_id",
                            "display_order",
                            "environment",
                            "criticality",
                        ]
                    }
                    | {
                        "version": r["version"],
                        "can_edit": r["status"] == "active"
                        and (actor.administrator or r["created_by"] == actor.user_id)
                        and "server:update" in actor.permissions,
                        "can_scan": r["status"] == "active"
                        and r["snapshot_id"] is not None
                        and (actor.administrator or r["created_by"] == actor.user_id)
                        and "server:inventory:manage" in actor.permissions,
                        "can_delete": r["status"] == "active"
                        and "server:inventory:manage" in actor.permissions
                        and (actor.administrator or r["created_by"] == actor.user_id),
                        "groups": [
                            {k: m[k] for k in ["id", "name", "display_order"]}
                            for m in memberships
                            if m["server_id"] == r["id"]
                        ],
                        "inventory": {
                            k: r[k]
                            for k in [
                                "snapshot_id",
                                "captured_at",
                                "processed_at",
                                "latest_snapshot_id",
                                "latest_captured_at",
                                "processing_status",
                                "collection_status",
                                "processing_error_code",
                                "package_count",
                                "service_count",
                                "container_count",
                                "image_count",
                                "os_name",
                                "os_version",
                                "distribution",
                                "release",
                                "architecture",
                                "kernel_version",
                                "sections",
                                "package_managers",
                                "inventory_freshness",
                                "inventory_max_age_hours",
                            ]
                        }
                        if inventory
                        else None,
                        "matching": {
                            k: r[k]
                            for k in ["last_matched_at", "evaluations", "current_evaluations"]
                        }
                        if r["can_findings"]
                        else None,
                        "open_findings": summary["n"] if r["can_findings"] else None,
                        "highest_priority": ["critical", "high", "medium", "low", "unrated"][
                            summary["level"]
                        ]
                        if r["can_findings"] and summary["level"] is not None
                        else None,
                    }
                )
            return {"items": items, "total": total["n"], "limit": limit, "offset": offset}
