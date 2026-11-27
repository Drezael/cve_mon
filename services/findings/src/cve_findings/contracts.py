"""Versioned policy and data-only jobs; absence of an SLA means no deadline."""

from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from cve_common.jobs.contracts import Payload
from cve_common.jobs.worker import WorkerSettings
from pydantic import AwareDatetime, Field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

RULE = "findings-1"
Lifecycle = Literal["open", "in_progress", "resolved", "closed"]
Priority = Literal["critical", "high", "medium", "low", "unrated"]


class Policy(Payload):
    rule_version: Literal["findings-1"] = "findings-1"
    automatic_resolution: bool = False
    exception_four_eyes: bool = False
    max_snapshot_age_hours: int | None = Field(default=None, ge=1, le=8760)
    kev_floor: Priority = "high"
    epss_high_threshold: Decimal | None = Field(default=None, ge=0, le=1)
    deadlines_hours: dict[Priority, int] = Field(default_factory=dict)
    deadline_warning_hours: int | None = Field(default=None, ge=1, le=8760)

    @model_validator(mode="after")
    def valid_policy(self) -> "Policy":
        if self.automatic_resolution and self.max_snapshot_age_hours is None:
            raise ValueError("Automatic resolution requires an approved freshness bound")
        if any(not 1 <= v <= 87600 for v in self.deadlines_hours.values()):
            raise ValueError("Invalid deadline duration")
        return self


class Settings(WorkerSettings):
    model_config = SettingsConfigDict(env_prefix="CVE_FINDINGS_")
    service_name: Literal["cve-findings"] = "cve-findings"
    guard_proof_file: Path
    concurrency: int = Field(default=2, ge=1, le=4)
    batch_size: int = Field(default=2, ge=1, le=4)
    maintenance_seconds: float = Field(default=60, ge=10, le=3600)

    @model_validator(mode="after")
    def identity(self) -> "Settings":
        if self.database.username != "findings_writer":
            raise ValueError("Dedicated findings database identity required")
        return self


class Request(Payload):
    event_id: UUID | None = None
    result_id: UUID | None = None
    current_version: int | None = Field(default=None, ge=1)
    identity: str | None = Field(default=None, pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$", max_length=256)
    finding_id: UUID | None = None
    after: UUID | None = None


class Result(Payload):
    count: int = 0
    finding_id: UUID | None = None
    changed: bool = False


class MatchingEvent(Payload):
    server_id: UUID
    snapshot_id: UUID
    identity: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$", max_length=256)
    enrichment_revision_id: UUID
    result_id: UUID
    rule_version: Literal["matching-1", "matching-2", "matching-3"]
    status: Literal["affected", "not_affected", "potentially_affected", "unknown", "not_applicable"]
    current_version: int = Field(ge=1)


class Reason(Payload):
    reason: str = Field(min_length=3, max_length=2048)

    @field_validator("reason")
    @classmethod
    def meaningful(cls, value: str) -> str:
        if len(value.strip()) < 3 or any(ord(c) < 32 and c not in "\n\t" for c in value):
            raise ValueError("A meaningful plain-text reason is required")
        return value.strip()


class Triage(Reason):
    action: Literal["start", "confirm", "needs_review", "suspect_false_positive", "fix_check"]


class Note(Reason):
    text: str = Field(min_length=1, max_length=4096)


class Assignment(Reason):
    assignee_user_id: UUID | None


class Review(Reason):
    decision: Literal[
        "confirmed", "suspected_false_positive", "confirmed_false_positive", "needs_review"
    ]
    evidence: str = Field(min_length=3, max_length=4096)
    result_id: UUID


class ExceptionRequest(Reason):
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    scope: Literal["basis", "episode"] = "basis"
    risk_context: str = Field(min_length=3, max_length=2048)

    @model_validator(mode="after")
    def valid_period(self) -> "ExceptionRequest":
        if self.valid_until <= self.valid_from:
            raise ValueError("Exception must have a finite increasing period")
        return self


class Mitigation(Reason):
    description: str = Field(min_length=3, max_length=2048)
    evidence: str = Field(min_length=3, max_length=4096)
    scope: str = Field(min_length=3, max_length=256)
    valid_until: AwareDatetime | None = None


class PolicyRequest(Reason):
    label: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
    configuration: Policy


class Signals(Payload):
    enrichment_revision_id: UUID | None = None
    cvss: dict[str, Any] | None = None
    kev_status: Literal["present", "absent", "unknown"] = "unknown"
    kev_is_current: bool = False
    kev_due_date: str | None = None
    epss: dict[str, Any] | None = None
    observed_at: datetime | None = None
