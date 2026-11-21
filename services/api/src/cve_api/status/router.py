"""Same-origin status read levels and versioned, audited maintenance metadata only."""

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from cve_common.jobs.contracts import Payload
from fastapi import APIRouter, Header, Query, Request
from pydantic import Field
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse

from cve_api.administration.versioning import check, etag
from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.errors import Denied
from cve_api.authorization.principal import Principal
from cve_api.findings.service import Findings
from cve_api.status.aggregation import availability, fresh, platform, worst
from cve_api.status.catalog import CATALOG, topological
from cve_api.status.collector import execute, rows
from cve_api.status.models import EntityListing, IncidentRead, Maintenance, OverviewRead
from cve_api.status.probes import control_health

router = APIRouter(prefix="/api/v1/status", tags=["status"])


def operation(
    request: Request, action: str = "deployment:status:read", mutation: bool = False
) -> Any:
    # Shared by personal SMTP and instance settings as well as status commands.
    return Findings(transport(request)[0]).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request) if mutation else None, action
    )


@asynccontextmanager
async def status_operation(
    request: Request, action: str = "deployment:status:read", mutation: bool = False
) -> AsyncIterator[tuple[AsyncSession, Principal]]:
    async with operation(request, action, mutation) as (session, actor):
        if not actor.administrator:
            raise Denied(403, "admin_role_required")
        yield session, actor


def ttl(request: Request) -> int:
    settings = getattr(request.app.state, "status_settings", None)
    return settings.stale_seconds if settings else 180


async def states(s: Any, request: Request) -> list[dict[str, Any]]:
    collector = getattr(request.app.state, "status_collector", None)
    if collector is not None:
        values: list[dict[str, Any]] = collector.cache.rows()
        control = collector.cache.read_control()
    else:
        values = await rows(
            s,
            (
                "SELECT e.id,e.kind,e.name,e.dependencies,e.critica"
                "l,c.raw_state,c.state,c.reason_code,c.observed_at,"
                "c.last_success_at,c.version,c.changes FROM status."
                "entities e LEFT JOIN status.current_states c ON c."
                "entity_id=e.id WHERE e.enabled ORDER BY e.kind,e.id LIMIT 32"
            ),
        )
        control = (await rows(s, "SELECT status.control_sample() AS value"))[0]["value"]
    now = datetime.now(UTC)
    request.state.status_control_sample = control
    for observation in control_health(control):
        for value in values:
            if value["id"] == observation.service_id:
                value.update(
                    state=observation.result,
                    raw_state=observation.result,
                    reason_code=observation.reason_code,
                    observed_at=now,
                )
    maintenance = await rows(
        s,
        (
            "SELECT id,service_ids,starts_at,ends_at FROM statu"
            "s.maintenance_windows WHERE NOT cancelled AND star"
            "ts_at<=:now AND ends_at>:now ORDER BY starts_at LI"
            "MIT 100"
        ),
        now=now,
    )
    for row in values:
        row["state"] = fresh(row["state"] or "unknown", row["observed_at"], now, ttl(request))
        row["stale"] = (
            row["state"] == "unknown"
            and row["observed_at"] is not None
            and (now - row["observed_at"]).total_seconds() > ttl(request)
        )
        row["reason_code"] = (
            "OBSERVATION_STALE" if row["stale"] else row["reason_code"] or "NO_OBSERVATION"
        )
        row["maintenance_ids"] = [w["id"] for w in maintenance if row["id"] in w["service_ids"]]
        row["display_state"] = "maintenance" if row["maintenance_ids"] else row["state"]
        row["dependency_hint"] = [
            d
            for d in row["dependencies"]
            if next((v["state"] for v in values if v["id"] == d), "unknown")
            in {"unavailable", "unknown"}
        ]
    by_id = {v["id"]: v for v in values}
    for key in topological():
        row = by_id.get(key, {})
        if (
            row
            and row["state"] == "healthy"
            and any(
                by_id.get(d, {}).get("state", "unknown") in {"unknown", "unavailable"}
                for d in row["dependencies"]
            )
        ):
            row["state"] = "degraded"
            row["reason_code"] = "DEPENDENCY_IMPAIRED"
            row["display_state"] = "maintenance" if row["maintenance_ids"] else "degraded"
    for row in values:
        if row["kind"] == "pipeline":
            row["state"] = worst([by_id[d]["state"] for d in row["dependencies"] if d in by_id])
            row["display_state"] = "maintenance" if row["maintenance_ids"] else row["state"]
    for row in values:
        row["dependency_hint"] = [
            d
            for d in row["dependencies"]
            if by_id.get(d, {}).get("state", "unknown") in {"unknown", "unavailable"}
        ]
    return values


def minimal(row: dict[str, Any]) -> dict[str, Any]:
    return {
        k: row[k]
        for k in [
            "id",
            "name",
            "kind",
            "state",
            "raw_state",
            "display_state",
            "observed_at",
            "stale",
            "maintenance_ids",
        ]
    }


@router.get("/overview", response_model=OverviewRead)
async def overview(request: Request) -> Any:
    async with status_operation(request) as (s, _actor):
        values = await states(s, request)
        services = [v for v in values if v["kind"] == "service"]
        observed = [v["observed_at"] for v in services if v["observed_at"]]
        incidents = await rows(
            s,
            "SELECT count(*) AS n FROM status.incidents i JOIN status.entities e "
            "ON e.id=i.entity_id WHERE e.enabled AND i.state='open'",
        )
        control = dict(request.state.status_control_sample)
        workflow, queue = control_health(control)
        control.update(
            state=worst([workflow.result, queue.result]),
            workflow_state=workflow.result,
            queue_state=queue.result,
        )
        return {
            "control": control,
            "schema_version": 1,
            "state": worst([platform(services), control["state"]]),
            "as_of": datetime.now(UTC),
            "last_observation_at": max(observed) if observed else None,
            "coverage": {
                "known": sum(v["state"] not in {"unknown", "starting"} for v in services),
                "total": len(services),
            },
            "services": [minimal(v) for v in services],
            "pipelines": [minimal(v) for v in values if v["kind"] == "pipeline"],
            "active_incidents": incidents[0]["n"],
        }


@router.get("/services", response_model=EntityListing)
@router.get("/pipelines", response_model=EntityListing)
async def listing(request: Request) -> Any:
    kind = "pipeline" if request.url.path.endswith("/pipelines") else "service"
    async with status_operation(request) as (s, _actor):
        values = [minimal(v) for v in await states(s, request) if v["kind"] == kind]
        return {"items": values, "total": len(values), "limit": 32, "offset": 0}


@router.get("/services/{identity}")
@router.get("/pipelines/{identity}")
async def detail(identity: str, request: Request) -> Any:
    key = "pipeline-" + identity if "/pipelines/" in request.url.path else identity
    async with status_operation(request, "deployment:diagnostics:read") as (s, _actor):
        value = next((v for v in await states(s, request) if v["id"] == key), None)
        if value is None:
            raise Denied(404)
        collector = getattr(request.app.state, "status_collector", None)
        if collector is not None:
            checks = collector.cache.checks(key)
        else:
            checks = await rows(
                s,
                (
                    "SELECT DISTINCT ON(o.check_id) o.check_id,o.checke"
                    "d_at,o.result,o.reason_code,o.metrics,o.duration_m"
                    "s,o.definition_version,d.stale_seconds FROM status"
                    ".check_observations o JOIN status.check_definition"
                    "s d ON (d.service_id,d.check_id,d.version)=(o.serv"
                    "ice_id,o.check_id,o.definition_version) WHERE o.se"
                    "rvice_id=:id AND o.run_id=(SELECT run_id FROM status.current_states "
                    "WHERE entity_id=:id) ORDER BY o.check_id,o.checked_at DESC"
                    ",o.id DESC LIMIT 32"
                ),
                id=key,
            )
        now = datetime.now(UTC)
        for item in checks:
            item["effective_state"] = fresh(
                item["result"], item["checked_at"], now, item["stale_seconds"]
            )
        value["checks"] = checks
        value["incidents"] = await rows(
            s,
            (
                "SELECT id,state,reason_code,opened_at FROM status."
                "incidents WHERE entity_id=:id AND state='open' ORD"
                "ER BY opened_at DESC LIMIT 1"
            ),
            id=key,
        )
        if collector is not None:
            value["flapping"] = collector.cache.recent_changes(key) >= 6
        else:
            recent = await rows(
                s,
                (
                    "SELECT count(*) AS n FROM status.state_history WHE"
                    "RE entity_id=:id AND observed_at>clock_timestamp()"
                    "-interval '15 minutes'"
                ),
                id=key,
            )
            value["flapping"] = recent[0]["n"] >= 6
        return value


@router.get("/services/{identity}/history")
@router.get("/pipelines/{identity}/history")
async def history(
    identity: str,
    request: Request,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
    hours: int = Query(24, ge=1, le=744),
    check_id: str = Query(
        "readiness", pattern="^(liveness|readiness|functional|backlog|freshness)$"
    ),
) -> Any:
    key = "pipeline-" + identity if "/pipelines/" in request.url.path else identity
    async with status_operation(request, "deployment:diagnostics:read") as (s, _actor):
        collector = getattr(request.app.state, "status_collector", None)
        if collector is not None:
            if key not in {v["id"] for v in collector.cache.rows()}:
                raise Denied(404)
            start = datetime.now(UTC) - timedelta(hours=hours)
            changes = [
                v
                for v in reversed(collector.cache.history.get(key, []))
                if v["observed_at"] >= start
            ]
            samples = [
                v
                for v in collector.cache.samples.get((key, check_id), [])
                if v["checked_at"] >= start
            ]
            return {
                "items": changes[offset : offset + limit],
                "total": len(changes),
                "limit": limit,
                "offset": offset,
                "samples": samples,
                "samples_capped": len(samples) == 2000,
                "availability": availability(samples, start, datetime.now(UTC), ttl(request))
                if not key.startswith("pipeline-")
                else None,
            }
        if not await rows(s, "SELECT id FROM status.entities WHERE id=:id", id=key):
            raise Denied(404)
        start = datetime.now(UTC) - timedelta(hours=hours)
        data = await rows(
            s,
            (
                "SELECT id,previous_state,state,raw_state,reason_co"
                "de,observed_at,decided_at,run_id,version FROM stat"
                "us.state_history WHERE entity_id=:id AND observed_"
                "at>=:start ORDER BY observed_at DESC,id LIMIT :lim"
                "it OFFSET :offset"
            ),
            id=key,
            start=start,
            limit=limit,
            offset=offset,
        )
        n = await rows(
            s,
            (
                "SELECT count(*) AS n FROM status.state_history WHE"
                "RE entity_id=:id AND observed_at>=:start"
            ),
            id=key,
            start=start,
        )
        samples = await rows(
            s,
            (
                "SELECT checked_at,result,duration_ms,metrics FROM "
                "status.check_observations WHERE service_id=:id AND"
                " check_id=:check AND checked_at>=:start ORDER BY c"
                "hecked_at DESC LIMIT 2000"
            ),
            id=key,
            check=check_id,
            start=start,
        )
        return {
            "items": data,
            "total": n[0]["n"],
            "limit": limit,
            "offset": offset,
            "samples": list(reversed(samples)),
            "samples_capped": len(samples) == 2000,
            "availability": availability(samples, start, datetime.now(UTC), ttl(request))
            if not key.startswith("pipeline-")
            else None,
        }


@router.get("/incidents")
async def incidents(
    request: Request,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
    state: Literal["open", "resolved"] | None = None,
    service_id: str | None = Query(None, max_length=64),
) -> Any:
    async with status_operation(request) as (s, _actor):
        where = (
            "(CAST(:state AS text) IS NULL OR i.state=:state) A"
            "ND (CAST(:service AS text) IS NULL OR i.entity_id="
            ":service) AND EXISTS(SELECT 1 FROM status.entities active "
            "WHERE active.id=i.entity_id AND active.enabled)"
        )
        values = {"state": state, "service": service_id, "limit": limit, "offset": offset}
        data = await rows(
            s,
            (
                "SELECT i.id,i.entity_id,e.name,i.state,i.reason_co"
                "de,i.opened_at,i.resolved_at,i.version FROM status"
                ".incidents i JOIN status.entities e ON e.id=i.enti"
                "ty_id WHERE "
            )
            + where
            + " ORDER BY i.opened_at DESC,i.id LIMIT :limit OFFSET :offset",
            **values,
        )
        n = await rows(s, "SELECT count(*) AS n FROM status.incidents i WHERE " + where, **values)
        return {"items": data, "total": n[0]["n"], "limit": limit, "offset": offset}


@router.get("/incidents/{identity}", response_model=IncidentRead)
async def incident(identity: UUID, request: Request) -> Any:
    async with status_operation(request) as (s, _actor):
        data = await rows(
            s,
            (
                "SELECT id,entity_id,state,reason_code,opened_at,re"
                "solved_at,version FROM status.incidents WHERE id=:"
                "id"
            ),
            id=identity,
        )
        if not data:
            raise Denied(404)
        return data[0]


@router.get("/incidents/{identity}/events")
async def events(
    identity: UUID,
    request: Request,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
) -> Any:
    async with status_operation(request) as (s, _actor):
        if not await rows(s, "SELECT id FROM status.incidents WHERE id=:id", id=identity):
            raise Denied(404)
        data = await rows(
            s,
            (
                "SELECT id,version,kind,reason_code,occurred_at FRO"
                "M status.incident_events WHERE incident_id=:id ORD"
                "ER BY occurred_at,id LIMIT :limit OFFSET :offset"
            ),
            id=identity,
            limit=limit,
            offset=offset,
        )
        n = await rows(
            s, "SELECT count(*) AS n FROM status.incident_events WHERE incident_id=:id", id=identity
        )
        return {"items": data, "total": n[0]["n"], "limit": limit, "offset": offset}


@router.get("/maintenance")
async def maintenance(
    request: Request, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0, le=100000)
) -> Any:
    async with status_operation(request) as (s, _actor):
        data = await rows(
            s,
            (
                "SELECT id,service_ids,starts_at,ends_at,descriptio"
                "n,cancelled,version FROM status.maintenance_window"
                "s ORDER BY starts_at DESC,id LIMIT :limit OFFSET :"
                "offset"
            ),
            limit=limit,
            offset=offset,
        )
        n = await rows(s, "SELECT count(*) AS n FROM status.maintenance_windows")
        return {"items": data, "total": n[0]["n"], "limit": limit, "offset": offset}


@router.get("/maintenance/{identity}")
async def maintenance_detail(identity: UUID, request: Request) -> Any:
    async with status_operation(request) as (s, _actor):
        data = await rows(
            s,
            (
                "SELECT id,service_ids,starts_at,ends_at,descriptio"
                "n,cancelled,version FROM status.maintenance_window"
                "s WHERE id=:id"
            ),
            id=identity,
        )
        if not data:
            raise Denied(404)
        return JSONResponse(
            json.loads(json.dumps(data[0], default=str)), headers={"ETag": etag(data[0]["version"])}
        )


@router.post("/admin/maintenance")
@router.put("/admin/maintenance/{identity}")
async def write_maintenance(
    body: Maintenance,
    request: Request,
    identity: UUID | None = None,
    if_match: Annotated[str | None, Header()] = None,
) -> Any:
    if set(body.service_ids) - set(CATALOG):
        raise Denied(422, "unknown_service")
    async with status_operation(request, "deployment:maintenance:manage", True) as (s, actor):
        old_value = None
        if identity:
            current = await rows(
                s,
                "SELECT * FROM status.maintenance_windows WHERE id=:id FOR UPDATE",
                id=identity,
            )
            if not current:
                raise Denied(404)
            old_value = current[0]
            check(current[0]["version"], if_match)
            version = current[0]["version"] + 1
            await execute(
                s,
                (
                    "UPDATE status.maintenance_windows SET service_ids="
                    ":services,starts_at=:start,ends_at=:end,descriptio"
                    "n=:description,actor_user_id=:actor,updated_at=clo"
                    "ck_timestamp(),version=:version WHERE id=:id"
                ),
                services=body.service_ids,
                start=body.starts_at,
                end=body.ends_at,
                description=body.description,
                actor=actor.user_id,
                version=version,
                id=identity,
            )
        else:
            identity = uuid4()
            version = 1
            await execute(
                s,
                (
                    "INSERT INTO status.maintenance_windows(id,service_"
                    "ids,starts_at,ends_at,description,actor_user_id) V"
                    "ALUES(:id,:services,:start,:end,:description,:acto"
                    "r)"
                ),
                id=identity,
                services=body.service_ids,
                start=body.starts_at,
                end=body.ends_at,
                description=body.description,
                actor=actor.user_id,
            )
        await execute(
            s,
            (
                "INSERT INTO status.audit(actor_user_id,object_id,a"
                "ction,reason,version,old_value,new_value) VALUES(:"
                "actor,:id,'maintenance_saved',:reason,:version,CAS"
                "T(:old AS jsonb),CAST(:new AS jsonb))"
            ),
            old=json.dumps(old_value, default=str),
            new=json.dumps(
                (
                    await rows(
                        s, ("SELECT * FROM status.maintenance_windows WHERE id=:id"), id=identity
                    )
                )[0],
                default=str,
            ),
            actor=actor.user_id,
            id=identity,
            reason=body.reason,
            version=version,
        )
        return JSONResponse(
            {"id": str(identity), "version": version}, headers={"ETag": etag(version)}
        )


class Cancel(Payload):
    reason: str = Field(min_length=3, max_length=256)


@router.delete("/admin/maintenance/{identity}")
async def cancel_maintenance(
    identity: UUID, body: Cancel, request: Request, if_match: Annotated[str | None, Header()] = None
) -> Any:
    async with status_operation(request, "deployment:maintenance:manage", True) as (s, actor):
        current = await rows(
            s, "SELECT * FROM status.maintenance_windows WHERE id=:id FOR UPDATE", id=identity
        )
        if not current:
            raise Denied(404)
        check(current[0]["version"], if_match)
        version = current[0]["version"] + 1
        await execute(
            s,
            (
                "UPDATE status.maintenance_windows SET cancelled=tr"
                "ue,version=:version,updated_at=clock_timestamp() W"
                "HERE id=:id"
            ),
            version=version,
            id=identity,
        )
        await execute(
            s,
            (
                "INSERT INTO status.audit(actor_user_id,object_id,a"
                "ction,reason,version,old_value,new_value) VALUES(:"
                "actor,:id,'maintenance_cancelled',:reason,:version"
                ",CAST(:old AS jsonb),CAST(:new AS jsonb))"
            ),
            old=json.dumps(current[0], default=str),
            new=json.dumps(
                (
                    await rows(
                        s, ("SELECT * FROM status.maintenance_windows WHERE id=:id"), id=identity
                    )
                )[0],
                default=str,
            ),
            actor=actor.user_id,
            id=identity,
            reason=body.reason,
            version=version,
        )
        return {"id": identity, "version": version}


class RestartRequest(Payload):
    reason: str = Field(min_length=3, max_length=256)


@router.post("/services/{identity}/restart", status_code=202)
async def restart_service(
    identity: str,
    body: RestartRequest,
    request: Request,
    idempotency_key: Annotated[UUID, Header()],
) -> Any:
    from cve_common.deployment import RESTART_TARGETS
    from sqlalchemy.exc import IntegrityError

    if identity not in RESTART_TARGETS:
        raise Denied(404)
    try:
        async with status_operation(request, "deployment:service:restart", True) as (s, actor):
            value = await rows(
                s,
                "SELECT status.request_restart(:id,:actor,:service,:reason) AS value",
                id=idempotency_key,
                actor=actor.user_id,
                service=identity,
                reason=body.reason,
            )
            return public_restart(value[0]["value"])
    except IntegrityError:
        raise Denied(409, "restart_already_pending_or_key_conflict") from None


def public_restart(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value[key]
        for key in (
            "id",
            "queue_id",
            "service_id",
            "state",
            "reason",
            "requested_at",
            "authorized_at",
            "started_at",
            "finished_at",
            "execution_id",
            "error_code",
        )
    }


@router.get("/admin/restarts")
async def restarts(request: Request) -> Any:
    from cve_common.deployment import GROUPS, RESTART_TARGETS

    async with status_operation(request, "deployment:service:restart") as (s, _actor):
        values = await rows(
            s, "SELECT * FROM status.service_restarts ORDER BY requested_at DESC LIMIT 25"
        )
        return {
            "items": [public_restart(value) for value in values],
            "targets": [
                {
                    "id": key,
                    "name": CATALOG[key].name,
                    "container": next(group for group, roles in GROUPS.items() if role in roles),
                }
                for key, role in RESTART_TARGETS.items()
            ],
        }
