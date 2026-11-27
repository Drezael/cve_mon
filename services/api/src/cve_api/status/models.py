"""Versioned, bounded, data-minimized monitoring contracts."""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID

from cve_common.jobs.contracts import Payload
from cve_common.jobs.worker import WorkerSettings
from pydantic import Field, field_validator, model_validator

State = Literal["healthy", "degraded", "unavailable", "unknown", "starting"]
Dimension = Literal["liveness", "readiness", "functional", "backlog", "freshness"]


class Settings(WorkerSettings):
    service_name: Literal["cve-status"] = "cve-status"
    concurrency: int = 1
    batch_size: int = 1
    lease_seconds: float = 60
    heartbeat_seconds: float = 10
    poll_seconds: float = 2
    interval_seconds: int = Field(default=60, ge=30, le=3600)
    stale_seconds: int = Field(default=180, ge=90, le=10800)
    timeout_seconds: float = Field(default=2, gt=0, le=5)
    parallel_checks: int = Field(default=4, ge=1, le=8)
    startup_seconds: int = Field(default=60, ge=0, le=300)
    retention_days: int = Field(default=14, ge=1, le=90)
    reports_dir: Path
    probe_key_file: Path
    dashboard_ca: Path
    notification_ca: Path | None = None
    dashboard_host: str
    dashboard_port: int = Field(default=8443, ge=1024, le=65535)

    @model_validator(mode="after")
    def context(self) -> "Settings":
        if (
            self.database.username != "status_probe"
            or self.stale_seconds < self.interval_seconds * 2
        ):
            raise ValueError("Dedicated status identity and freshness headroom required")
        if not self.dashboard_host or any(
            c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in self.dashboard_host
        ):
            raise ValueError("DNS name required")
        return self


class Observation(Payload):
    schema_version: Literal[1] = 1
    service_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,47}$")
    check_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,47}$")
    checked_at: datetime
    result: State
    duration_ms: float = Field(ge=0, le=60000, allow_inf_nan=False)
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    metrics: dict[str, float | int | None] = Field(default_factory=dict, max_length=32)

    @field_validator("metrics")
    @classmethod
    def metrics_allowlist(
        cls, values: dict[str, float | int | None]
    ) -> dict[str, float | int | None]:
        allowed = {
            "queued",
            "running",
            "retry_pending",
            "failed",
            "expired_leases",
            "oldest_seconds",
            "last_success_age_seconds",
            "heartbeat_age_seconds",
            "completed",
            "duration_ms",
            "error_rate",
            "queue_size",
            "deferred",
            "oldest_deferred_seconds",
            "upstream_failures",
            "pending",
            "uncertain",
            "relay_accepted",
            "uncovered",
            "capped",
            "next_due_seconds",
            "api_requests",
            "api_errors",
            "api_mean_latency_ms",
            "collector_cpu_seconds",
            "collector_rss_bytes",
        }
        if set(values) - allowed or any(
            v is not None and (not __import__("math").isfinite(v) or v < 0) for v in values.values()
        ):
            raise ValueError("Finite aggregate metric allowlist required")
        return values

    @field_validator("checked_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("UTC-aware timestamp required")
        return value


class Collect(Payload):
    pass


class Maintenance(Payload):
    service_ids: list[str] = Field(min_length=1, max_length=20)
    starts_at: datetime
    ends_at: datetime
    description: str = Field(min_length=3, max_length=512)
    reason: str = Field(min_length=3, max_length=256)

    @model_validator(mode="after")
    def finite(self) -> "Maintenance":
        if (
            self.starts_at.tzinfo is None
            or self.ends_at.tzinfo is None
            or self.ends_at <= self.starts_at
            or self.ends_at - self.starts_at > timedelta(days=90)
            or len(set(self.service_ids)) != len(self.service_ids)
        ):
            raise ValueError("Unique services and finite aware maintenance window required")
        return self


class EntityRead(Payload):
    schema_version: Literal[1] = 1
    id: str
    name: str
    kind: Literal["service", "pipeline"]
    state: State
    raw_state: State | None
    display_state: Literal[
        "healthy", "degraded", "unavailable", "unknown", "starting", "maintenance"
    ]
    observed_at: datetime | None
    stale: bool
    maintenance_ids: list[UUID]


class Coverage(Payload):
    known: int = Field(ge=0, le=32)
    total: int = Field(ge=0, le=32)


class ControlRead(Payload):
    enabled: bool | None
    sample_stale: bool = False
    sample_checked_at: datetime | None = None
    state: State
    workflow_state: State
    queue_state: State
    heartbeat_at: datetime | None
    pending: int | None
    processing: int | None
    paused: int | None
    failed: int | None
    oldest_seconds: float | None
    expired_leases: int | None
    capped: bool


class OverviewRead(Payload):
    control: ControlRead | None = None
    schema_version: Literal[1] = 1
    state: State
    as_of: datetime
    last_observation_at: datetime | None
    coverage: Coverage
    services: list[EntityRead]
    pipelines: list[EntityRead]
    active_incidents: int = Field(ge=0)


class EntityListing(Payload):
    items: list[EntityRead]
    total: int = Field(ge=0, le=32)
    limit: Literal[32]
    offset: Literal[0]


class IncidentRead(Payload):
    id: UUID
    entity_id: str
    state: Literal["open", "resolved"]
    reason_code: str
    opened_at: datetime
    resolved_at: datetime | None
    version: int = Field(ge=1)
