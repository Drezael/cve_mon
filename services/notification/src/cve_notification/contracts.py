"""Finite notification policies; network destinations and recipients are never job input."""

from datetime import time
from decimal import Decimal
from pathlib import Path
from typing import Literal
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cve_common.jobs.contracts import Payload
from cve_common.jobs.worker import WorkerSettings
from pydantic import Field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

STATUS_EVENTS = frozenset({"status_unavailable", "status_recovered"})

EVENTS = frozenset(
    [
        "created",
        "confirmed_affected",
        "potentially_affected",
        "reopened",
        "priority_changed",
        "resolved",
        "closed",
        "assigned",
        "deadline_approaching",
        "overdue",
        "exception_approved",
        "exception_approaching",
        "exception_expired",
        "exception_revoked",
    ]
)
Priority = Literal["unrated", "low", "medium", "high", "critical"]
STATUS = frozenset(
    [
        "planned",
        "suppressed",
        "deferred",
        "ready",
        "leased",
        "submitting",
        "relay_accepted",
        "retryable_failure",
        "permanent_failure",
        "submission_uncertain",
        "upstream_accepted",
        "bounced",
        "delivery_confirmed",
        "cancelled",
    ]
)


class Quiet(Payload):
    timezone: str = "Europe/Berlin"
    start: time = time(22)
    end: time = time(7)
    weekdays: list[int] = Field(default_factory=lambda: list(range(7)), min_length=1, max_length=7)

    @field_validator("timezone")
    @classmethod
    def zone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError:
            raise ValueError("Unknown timezone") from None
        return value

    @model_validator(mode="after")
    def bounds(self) -> "Quiet":
        if self.start == self.end or any(d not in range(7) for d in self.weekdays):
            raise ValueError("Finite quiet window required")
        if self.start.tzinfo or self.end.tzinfo:
            raise ValueError("Local wall times required")
        return self


class Preferences(Payload):
    enabled: bool = True
    mode: Literal["immediate", "digest"] = "immediate"
    minimum_priority: Priority = "unrated"
    digest_hours: Literal[1, 24, 168] = 24
    timezone: str = "Europe/Berlin"
    language: Literal["de"] = "de"
    quiet: Quiet | None = None
    event_types: list[str] = Field(default_factory=lambda: sorted(EVENTS))

    @field_validator("timezone")
    @classmethod
    def zone(cls, value: str) -> str:
        return Quiet.zone(value)

    @field_validator("event_types")
    @classmethod
    def events(cls, value: list[str]) -> list[str]:
        if not set(value) <= EVENTS | STATUS_EVENTS:
            raise ValueError("Unsupported finding event")
        return sorted(set(value))


class Rule(Payload):
    enabled: bool = True
    event_types: list[str] = Field(default_factory=lambda: sorted(EVENTS), min_length=1)
    minimum_priority: Priority = "high"
    priority_direction: Literal["increase", "any"] = "increase"
    lifecycle: list[Literal["open", "in_progress", "resolved", "closed"]] = Field(
        default_factory=list
    )
    technical: list[
        Literal["affected", "potentially_affected", "unknown", "not_affected", "not_applicable"]
    ] = Field(default_factory=list)
    kev_only: bool = False
    minimum_cvss: Decimal | None = Field(default=None, ge=0, le=10)
    minimum_epss: Decimal | None = Field(default=None, ge=0, le=1)
    recipients: Literal["assignee", "administrators", "authorized", "server_owner"] = "assignee"
    mode: Literal["immediate", "digest"] = "immediate"
    mandatory: bool = False
    critical_bypass: bool = False
    suppress_active_exception: bool = False
    rate_per_hour: int = Field(default=10, ge=1, le=100)
    max_deferral_hours: int = Field(default=168, ge=1, le=720)
    exception_warning_hours: int = Field(default=24, ge=1, le=720)
    digest_hours: Literal[1, 24, 168] = 24
    quiet: Quiet | None = None
    allowed_domains: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("event_types")
    @classmethod
    def events(cls, value: list[str]) -> list[str]:
        return Preferences.events(value)

    @field_validator("allowed_domains")
    @classmethod
    def domains(cls, values: list[str]) -> list[str]:
        import re

        if any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,63}", v)
            for v in values
        ):
            raise ValueError("Explicit DNS domains required")
        return sorted(set(values))


class RuleChange(Payload):
    rule: Rule
    reason: str = Field(min_length=3, max_length=1024)


class Template(Payload):
    name: Literal["finding", "digest"]
    language: Literal["de"] = "de"
    subject: str = Field(min_length=1, max_length=160)
    text: str = Field(min_length=1, max_length=8192)
    html: str = Field(min_length=1, max_length=8192)

    @model_validator(mode="after")
    def safe(self) -> "Template":
        from cve_notification.rendering import validate_template

        validate_template(self)
        return self


class TemplateChange(Payload):
    template: Template
    reason: str = Field(min_length=3, max_length=1024)


class Request(Payload):
    event_id: UUID | None = None
    notification_id: UUID | None = None
    after: UUID | None = None


class Result(Payload):
    count: int = 0


class Settings(WorkerSettings):
    model_config = SettingsConfigDict(env_prefix="CVE_NOTIFICATION_")
    service_name: Literal["cve-notification"] = "cve-notification"
    guard_proof_file: Path
    configuration_dir: Path
    concurrency: int = Field(default=1, ge=1, le=4)
    batch_size: int = Field(default=1, ge=1, le=4)
    maintenance_seconds: float = Field(default=60, ge=10, le=3600)

    @model_validator(mode="after")
    def role(self) -> "Settings":
        if self.database.username != "notification":
            raise ValueError("Dedicated notification identity required")
        return self
