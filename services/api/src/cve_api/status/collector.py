"""One durable, fenced collector in the existing API process and PostgreSQL job runtime."""

import asyncio
import contextlib
import json
import logging
import random
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_common.jobs.contracts import JobEnvelope, Payload
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import JobDefinition, Registry
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker
from cve_common.workflows import centrally_controlled
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.status import probes
from cve_api.status.aggregation import transition, worst
from cve_api.status.cache import StatusCache
from cve_api.status.catalog import CATALOG, HTTP_TARGETS, PIPELINES, topological
from cve_api.status.models import Collect, Observation, Settings, State

LOG = logging.getLogger("cve.status")


async def rows(s: AsyncSession, sql: str, **values: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in (await s.execute(text(sql), values)).mappings().all()]


async def execute(s: AsyncSession, sql: str, **values: Any) -> None:
    await s.execute(text(sql), values)


class Collector:
    def __init__(self, settings: Settings, *, epss_enabled: bool = True) -> None:
        self.settings = settings
        self.epss_enabled = epss_enabled
        self.started_at = datetime.now(UTC)
        self.cache = StatusCache(settings.stale_seconds)
        self.pending_incidents: dict[str, dict[str, Any]] = {}
        self.database = Database(settings.database)
        registry = Registry()
        registry.register(JobDefinition("status.collect", 1, Collect, None, self.handle, 45, 1))
        self.repository = JobRepository(self.database, registry)
        self.worker = Worker(self.repository, settings)
        self.stop = asyncio.Event()
        self.tasks: list[asyncio.Task[None]] = []

    async def open(self) -> None:
        self.database.open()
        self.tasks = [
            asyncio.create_task(self.worker.run(self.stop)),
            asyncio.create_task(self.schedule()),
        ]

    async def close(self) -> None:
        self.stop.set()
        await asyncio.gather(*self.tasks)
        await self.database.close()

    async def schedule(self) -> None:
        if self.settings.paused:
            await self.stop.wait()
            return
        while not self.stop.is_set():
            try:
                async with transaction(self.database) as s:
                    slot = int(datetime.now(UTC).timestamp()) // self.settings.interval_seconds
                    if not await centrally_controlled(s):
                        await self.repository.enqueue(
                            s,
                            JobEnvelope(
                                job_type="status.collect",
                                payload={},
                                idempotency_key=f"status:{slot}",
                                max_attempts=1,
                                scope="monitoring",
                            ),
                        )
            except (SQLAlchemyError, OSError):
                LOG.warning("collector_scheduler_unavailable")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    self.stop.wait(), self.settings.interval_seconds + random.uniform(0, 5)
                )

    async def gather(self) -> list[Observation]:
        semaphore = asyncio.Semaphore(self.settings.parallel_checks)

        async def check(service: str, dimension: str) -> Observation:
            async with semaphore:
                LOG.info("check_started", extra={"service_id": service, "check_id": dimension})
                result = await probes.http(self.settings, service, dimension)
                LOG.info(
                    "check_completed",
                    extra={
                        "service_id": service,
                        "check_id": dimension,
                        "result": result.result,
                        "reason_code": result.reason_code,
                        "duration_ms": result.duration_ms,
                    },
                )
                return result

        futures = [
            check(service, d)
            for service in [*HTTP_TARGETS, "nginx"]
            for d in ["liveness", "readiness"]
        ]
        values = list(await asyncio.gather(*futures))
        from cve_common.http.metrics import snapshot as own_process_metrics

        values = [
            v.model_copy(update={"metrics": {**v.metrics, **own_process_metrics()}})
            if v.service_id == "api" and v.check_id == "readiness"
            else v
            for v in values
        ]
        values.extend(probes.local(self.settings, service) for service in ["postfix"])

        async def diagnostic(function: str) -> dict[str, Any] | None:
            try:
                async with (
                    asyncio.timeout(self.settings.timeout_seconds),
                    transaction(self.database) as s,
                ):
                    return cast(
                        dict[str, Any], (await s.execute(text("SELECT " + function))).scalar_one()
                    )
            except (SQLAlchemyError, TimeoutError, OSError):
                LOG.warning("status_diagnostic_unavailable", extra={"check_id": function})
                return None

        data, control = await asyncio.gather(
            diagnostic("status.sample()"), diagnostic("status.control_sample()")
        )
        if control is not None:
            self.cache.set_control(control)
        values.extend(probes.control_health(self.cache.read_control()))
        if data is None:
            values.append(
                probes.observation(
                    "postgres",
                    "readiness",
                    "healthy" if control is not None else "unknown",
                    "DATABASE_READY" if control is not None else "DATABASE_SAMPLE_UNAVAILABLE",
                )
            )
            values.extend(
                probes.observation(key, "backlog", "unknown", "DATABASE_SAMPLE_UNAVAILABLE")
                for key in ("jobs", "outbox")
            )
            return values
        values.append(
            probes.observation(
                "postgres",
                "readiness",
                "healthy" if data["schema_ready"] else "unknown",
                "DATABASE_READY" if data["schema_ready"] else "MIGRATION_MISMATCH",
            )
        )
        for key in ["jobs", "outbox", "intake"]:
            if key == "jobs":
                metrics = {
                    k: sum((j.get(k) or 0) for j in data["jobs"])
                    for k in [
                        "queued",
                        "running",
                        "retry_pending",
                        "failed",
                        "expired_leases",
                        "completed",
                    ]
                }
                metrics["oldest_seconds"] = max(
                    (j.get("oldest_seconds") or 0 for j in data["jobs"]), default=0
                )
                metrics["capped"] = int(data["capped"])
            else:
                metrics = data[key]
            values.append(probes.backlog(key, metrics))
        for key, service in CATALOG.items():
            if service.job_prefix:
                matching = [j for j in data["jobs"] if j["job_type"].startswith(service.job_prefix)]
                metrics = {
                    k: sum((j.get(k) or 0) for j in matching)
                    for k in [
                        "queued",
                        "running",
                        "retry_pending",
                        "failed",
                        "expired_leases",
                        "completed",
                    ]
                }
                for k in ["oldest_seconds", "heartbeat_age_seconds"]:
                    metrics[k] = max((j.get(k) or 0 for j in matching), default=0)
                ages = [
                    j["last_success_age_seconds"]
                    for j in matching
                    if j.get("last_success_age_seconds") is not None
                ]
                metrics["last_success_age_seconds"] = min(ages) if ages else None
                if key == "notification":
                    intents = data["notification"]
                    metrics["oldest_seconds"] = max(
                        metrics.get("oldest_seconds") or 0, intents.get("oldest_seconds") or 0
                    )
                    for field in ["pending", "uncertain", "capped"]:
                        metrics[field] = intents.get(field) or 0
                values.append(probes.backlog(key, metrics, service.backlog_seconds))
        uncovered = data["matching"]["uncovered"]
        values.append(
            probes.observation(
                "matcher",
                "freshness",
                "degraded" if uncovered else "healthy",
                "MATCHING_NOT_CURRENT" if uncovered else "CURRENT_EVALUATIONS_OR_EMPTY_INVENTORY",
                {"uncovered": uncovered},
            )
        )
        if self.epss_enabled:
            epss = data["enrichment"]
            values.append(
                probes.observation(
                    "enricher",
                    "freshness",
                    "unknown"
                    if epss["stale"] is None
                    else "degraded"
                    if epss["stale"]
                    else "healthy",
                    "EPSS_NOT_CONFIGURED_OR_ABSENT"
                    if epss["stale"] is None
                    else "EPSS_STALE"
                    if epss["stale"]
                    else "EPSS_CURRENT",
                    {"last_success_age_seconds": epss["last_success_age_seconds"]},
                )
            )
        else:
            values.append(probes.observation("enricher", "freshness", "healthy", "EPSS_DISABLED"))
        values.append(
            probes.backlog("notification", data["workflow"]).model_copy(
                update={"check_id": "functional"}
            )
        )
        postfix = next(o for o in values if o.service_id == "postfix" and o.check_id == "readiness")
        if postfix.result == "healthy" and "queue_size" in postfix.metrics:
            values.append(
                probes.backlog(
                    "postfix",
                    {
                        "pending": postfix.metrics["queue_size"],
                        "oldest_seconds": postfix.metrics.get("oldest_seconds"),
                        "capped": postfix.metrics.get("capped"),
                    },
                )
            )
        else:
            values.append(
                probes.observation("postfix", "backlog", "unknown", "QUEUE_SAMPLE_UNAVAILABLE")
            )
        sources = data["sources"]
        if sources:
            now = datetime.now(UTC)
            missed = any(
                not row["last_success"]
                or (now - datetime.fromisoformat(row["last_success"])).total_seconds()
                > row["max_age_seconds"]
                for row in sources
            )
            values.append(
                probes.observation(
                    "importer",
                    "freshness",
                    "degraded" if missed else "healthy",
                    "SOURCE_OVERDUE" if missed else "SOURCE_WITHIN_SCHEDULE",
                )
            )
        else:
            values.append(
                probes.observation(
                    "importer",
                    "freshness",
                    "healthy" if not data.get("source_auto_updates", True) else "unknown",
                    "MANUAL_UPDATE_POLICY"
                    if not data.get("source_auto_updates", True)
                    else "SOURCE_EXPECTATION_NOT_CONFIGURED",
                )
            )
        return values

    async def handle(self, ctx: ExecutionContext, _payload: BaseModel) -> None:
        started = datetime.now(UTC)
        observations = await self.gather()
        for changed in self.cache.publish(observations):
            self.pending_incidents[changed["id"]] = changed
        pending = dict(self.pending_incidents)

        async def save(s: AsyncSession) -> Payload | None:
            if pending:
                run = uuid4()
                await execute(s, "SELECT pg_advisory_xact_lock(220030)")
                await execute(
                    s,
                    "INSERT INTO status.monitoring_runs(id,started_at,finished_at,"
                    "correlation_id,observation_count) VALUES(:id,:start,:end,:correlation,:n)",
                    id=run,
                    start=started,
                    end=datetime.now(UTC),
                    correlation=ctx.job.correlation_id,
                    n=len(observations),
                )
                for key, row in pending.items():
                    service = CATALOG[key]
                    await execute(
                        s,
                        "INSERT INTO status.entities(id,kind,name,dependencies,critical) "
                        "VALUES(:id,'service',:name,:dependencies,:critical) "
                        "ON CONFLICT(id) DO NOTHING",
                        id=key,
                        name=service.name,
                        dependencies=list(service.dependencies),
                        critical=service.critical,
                    )
                    await self.incident(
                        s, key, row["state"], row["reason_code"], row["observed_at"], run, True
                    )
            return None

        # Live measurements are already visible even if incident persistence fails.
        # Persist only durable incident transitions; no current_states/observations writes.
        await ctx.complete(save)
        for key, row in pending.items():
            if self.pending_incidents.get(key) is row:
                del self.pending_incidents[key]

    async def collect(self) -> UUID:
        started = datetime.now(UTC)
        observations = await self.gather()
        async with transaction(self.database) as s:
            return await self.persist(s, observations, started, uuid4())

    async def persist(
        self, s: AsyncSession, observations: list[Observation], started: datetime, correlation: UUID
    ) -> UUID:
        await execute(s, "SELECT pg_advisory_xact_lock(220030)")
        run = uuid4()
        now = datetime.now(UTC)
        await execute(
            s,
            (
                "INSERT INTO status.monitoring_runs(id,started_at,f"
                "inished_at,correlation_id,observation_count) VALUE"
                "S(:id,:start,:end,:correlation,:n)"
            ),
            id=run,
            start=started,
            end=now,
            correlation=correlation,
            n=len(observations),
        )
        for key in topological():
            service = CATALOG[key]
            await execute(
                s,
                (
                    "INSERT INTO status.entities(id,kind,name,dependenc"
                    "ies,critical) VALUES(:id,'service',:name,:dependen"
                    "cies,:critical) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,"
                    "dependencies=EXCLUDED.dependencies,critical=EXCLUDED.critical"
                ),
                id=key,
                name=service.name,
                dependencies=list(service.dependencies),
                critical=service.critical,
            )
        for key, (name, members) in PIPELINES.items():
            await execute(
                s,
                (
                    "INSERT INTO status.entities(id,kind,name,dependenc"
                    "ies) VALUES(:id,'pipeline',:name,:members) ON CONF"
                    "LICT(id) DO UPDATE SET name=EXCLUDED.name,dependencies=EXCLUDED.dependencies"
                ),
                id="pipeline-" + key,
                name=name,
                members=list(members),
            )
        for item in observations:
            if (
                item.service_id not in CATALOG
                or item.checked_at > now
                or (now - item.checked_at).total_seconds() > self.settings.stale_seconds
            ):
                raise ValueError("Untrusted or stale collector observation")
            configuration = {
                "timeout_seconds": self.settings.timeout_seconds,
                "backlog_seconds": CATALOG[item.service_id].backlog_seconds,
            }
            definitions = await rows(
                s,
                (
                    "SELECT * FROM status.check_definitions WHERE servi"
                    "ce_id=:service AND check_id=:check ORDER BY versio"
                    "n DESC LIMIT 1"
                ),
                service=item.service_id,
                check=item.check_id,
            )
            previous = definitions[0] if definitions else None
            version = int(previous["version"]) if previous else 1
            if previous and (
                previous["configuration"] != configuration
                or previous["interval_seconds"] != self.settings.interval_seconds
                or previous["stale_seconds"] != self.settings.stale_seconds
            ):
                version += 1
                previous = None
            if not previous:
                await execute(
                    s,
                    (
                        "INSERT INTO status.check_definitions(service_id,ch"
                        "eck_id,version,dimension,interval_seconds,stale_se"
                        "conds,configuration) VALUES(:service,:check,:versi"
                        "on,:dimension,:interval,:stale,CAST(:configuration"
                        " AS jsonb))"
                    ),
                    service=item.service_id,
                    check=item.check_id,
                    version=version,
                    dimension=item.check_id,
                    interval=self.settings.interval_seconds,
                    stale=self.settings.stale_seconds,
                    configuration=json.dumps(configuration),
                )
            await execute(
                s,
                (
                    "INSERT INTO status.check_observations(run_id,servi"
                    "ce_id,check_id,definition_version,checked_at,resul"
                    "t,duration_ms,reason_code,metrics) VALUES(:run,:se"
                    "rvice,:check,:version,:at,:result,:duration,:reaso"
                    "n,CAST(:metrics AS jsonb))"
                ),
                run=run,
                service=item.service_id,
                check=item.check_id,
                version=version,
                at=item.checked_at,
                result=item.result,
                duration=item.duration_ms,
                reason=item.reason_code,
                metrics=json.dumps(item.metrics),
            )
        states: dict[str, State] = {}
        for key in topological():
            items = [o for o in observations if o.service_id == key]
            state = worst([o.result for o in items])
            reason = next((o.reason_code for o in items if o.result == state), "NO_OBSERVATION")
            raw = state
            dependencies = [states[d] for d in CATALOG[key].dependencies]
            if any(d in {"unavailable", "unknown"} for d in dependencies) and state == "healthy":
                state = "degraded"
                reason = "DEPENDENCY_IMPAIRED"
            at = max((o.checked_at for o in items), default=now)
            states[key] = await self.state(
                s,
                key,
                raw,
                state,
                reason,
                at,
                run,
                allow_alert=not any(d in {"unavailable", "unknown"} for d in dependencies),
            )
        for key, (_, members) in PIPELINES.items():
            state = worst([states[m] for m in members])
            await self.state(s, "pipeline-" + key, state, state, "PIPELINE_MEMBERS", now, run)
        await execute(s, "SELECT status.prune(:days)", days=self.settings.retention_days)
        LOG.info(
            "collector_completed",
            extra={
                "run_id": str(run),
                "correlation_id": str(correlation),
                "observation_count": len(observations),
            },
        )
        return run

    async def state(
        self,
        s: AsyncSession,
        key: str,
        raw: State,
        candidate: State,
        reason: str,
        at: datetime,
        run: UUID,
        *,
        allow_alert: bool = True,
    ) -> State:
        old = await rows(
            s, "SELECT * FROM status.current_states WHERE entity_id=:id FOR UPDATE", id=key
        )
        previous = old[0] if old else None
        if previous and at <= previous["observed_at"]:
            return cast(State, previous["state"])
        if (
            previous
            and (at - previous["observed_at"]).total_seconds() > self.settings.stale_seconds
        ):
            gap_at = previous["observed_at"] + timedelta(seconds=self.settings.stale_seconds)
            gap_version = int(previous["version"]) + 1
            await execute(
                s,
                (
                    "INSERT INTO status.state_history(entity_id,previou"
                    "s_state,state,raw_state,reason_code,observed_at,ru"
                    "n_id,version) VALUES(:id,:old,'unknown','unknown',"
                    "'MONITORING_GAP',:at,:run,:version)"
                ),
                id=key,
                old=previous["state"],
                at=gap_at,
                run=run,
                version=gap_version,
            )
            await self.incident(
                s, key, "unknown", "MONITORING_GAP", gap_at, run, True, allow_alert=False
            )
            previous = {**previous, "state": "unknown", "successes": 0, "version": gap_version}
        if (
            previous is None
            and candidate == "unknown"
            and reason in {"TRANSPORT_OR_SCHEMA_ERROR", "CHECK_TIMEOUT"}
            and (at - self.started_at).total_seconds() < self.settings.startup_seconds
        ):
            candidate, reason = "starting", "STARTUP_GRACE"
        effective, failures, successes = transition(previous, candidate)
        version = int(previous["version"]) + 1 if previous else 1
        changed = not previous or previous["state"] != effective
        changes = (int(previous["changes"]) if previous else 0) + int(changed)
        await execute(
            s,
            (
                "INSERT INTO status.current_states(entity_id,raw_st"
                "ate,state,reason_code,observed_at,last_success_at,"
                "run_id,failures,successes,changes,version) VALUES("
                ":id,:raw,:state,:reason,:at,:success,:run,:failure"
                "s,:successes,:changes,:version) ON CONFLICT(entity"
                "_id) DO UPDATE SET raw_state=excluded.raw_state,st"
                "ate=excluded.state,reason_code=excluded.reason_cod"
                "e,observed_at=excluded.observed_at,last_success_at"
                "=coalesce(excluded.last_success_at,status.current_"
                "states.last_success_at),run_id=excluded.run_id,fai"
                "lures=excluded.failures,successes=excluded.success"
                "es,changes=excluded.changes,version=excluded.versi"
                "on"
            ),
            id=key,
            raw=raw,
            state=effective,
            reason=reason,
            at=at,
            success=at if candidate == "healthy" else None,
            run=run,
            failures=failures,
            successes=successes,
            changes=changes,
            version=version,
        )
        if changed:
            await execute(
                s,
                (
                    "INSERT INTO status.state_history(entity_id,previou"
                    "s_state,state,raw_state,reason_code,observed_at,ru"
                    "n_id,version) VALUES(:id,:old,:state,:raw,:reason,"
                    ":at,:run,:version)"
                ),
                id=key,
                old=previous["state"] if previous else None,
                state=effective,
                raw=raw,
                reason=reason,
                at=at,
                run=run,
                version=version,
            )
        await self.incident(s, key, effective, reason, at, run, changed, allow_alert=allow_alert)
        return effective

    async def incident(
        self,
        s: AsyncSession,
        key: str,
        state: State,
        reason: str,
        at: datetime,
        run: UUID,
        changed: bool,
        *,
        allow_alert: bool = True,
    ) -> None:
        found = await rows(
            s,
            "SELECT * FROM status.incidents WHERE entity_id=:id AND state='open' FOR UPDATE",
            id=key,
        )
        current = found[0] if found else None
        if state == "starting" and not current:
            return
        if state == "healthy" and not current or state != "healthy" and current and not changed:
            return
        if state == "healthy":
            assert current
            version = current["version"] + 1
            identity = current["id"]
            kind = "recovered"
            await execute(
                s,
                (
                    "UPDATE status.incidents SET state='resolved',resol"
                    "ved_at=:at,version=:version WHERE id=:id"
                ),
                at=at,
                version=version,
                id=identity,
            )
        elif current:
            version = current["version"] + 1
            identity = current["id"]
            kind = "changed"
            await execute(
                s,
                "UPDATE status.incidents SET reason_code=:reason,version=:version WHERE id=:id",
                reason=reason,
                version=version,
                id=identity,
            )
        else:
            identity = uuid4()
            version = 1
            kind = "opened"
            await execute(
                s,
                (
                    "INSERT INTO status.incidents(id,entity_id,state,re"
                    "ason_code,opened_at) VALUES(:id,:entity,'open',:re"
                    "ason,:at)"
                ),
                id=identity,
                entity=key,
                reason=reason,
                at=at,
            )
        await execute(
            s,
            (
                "INSERT INTO status.incident_events(incident_id,ver"
                "sion,kind,reason_code,run_id) VALUES(:id,:version,"
                ":kind,:reason,:run)"
            ),
            id=identity,
            version=version,
            kind=kind,
            reason=reason,
            run=run,
        )
        # Only direct critical service outages and their recovery. No pipeline duplicates,
        # no alert about the notification worker itself, no periodic alarm repetition.
        if (
            allow_alert
            and key in CATALOG
            and CATALOG[key].critical
            and key != "notification"
            and kind in {"opened", "recovered"}
            and (state == "unavailable" or kind == "recovered")
        ):
            event_kind = "status_recovered" if kind == "recovered" else "status_unavailable"
            if kind != "recovered" or await rows(
                s,
                "SELECT event_id FROM status.alert_receipts WHERE incident_id=:id LIMIT 1",
                id=identity,
            ):
                payload = {
                    "schema_version": 1,
                    "incident_id": str(identity),
                    "entity_id": key,
                    "incident_version": version,
                    "state": state,
                    "reason_code": reason,
                }
                event_id = uuid4()
                await execute(
                    s,
                    (
                        "SELECT automation.emit_event(:id,:type,1,'cve-stat"
                        "us','status_incident',:incident,:version,CAST(:pay"
                        "load AS jsonb),:key,:correlation)"
                    ),
                    id=event_id,
                    type="monitoring." + event_kind,
                    incident=str(identity),
                    version=version,
                    payload=json.dumps(payload),
                    key=f"status:{identity}:{version}",
                    correlation=run,
                )
                await execute(
                    s,
                    (
                        "INSERT INTO status.alert_receipts(incident_id,inci"
                        "dent_version,event_id) VALUES(:id,:version,:event)"
                    ),
                    id=identity,
                    version=version,
                    event=event_id,
                )
        LOG.info(
            "incident_" + kind,
            extra={"incident_id": str(identity), "service_id": key, "reason_code": reason},
        )
