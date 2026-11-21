"""Typed revision-bound requests; no raw inventories in jobs or events."""

from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from cve_common.jobs.contracts import Payload
from cve_common.jobs.worker import WorkerSettings
from pydantic import Field, model_validator
from pydantic_settings import SettingsConfigDict

RULE: Literal["matching-1"] = "matching-1"
Status = Literal["affected", "not_affected", "potentially_affected", "unknown", "not_applicable"]


class Settings(WorkerSettings):
    model_config = SettingsConfigDict(env_prefix="CVE_MATCHER_")
    service_name: Literal["cve-matcher"] = "cve-matcher"
    processes: int = Field(default=1, ge=1, le=2)
    guard_proof_file: Path
    concurrency: int = Field(default=2, ge=1, le=4)
    batch_size: int = Field(default=2, ge=1, le=4)

    @model_validator(mode="after")
    def identity(self) -> "Settings":
        if self.database.username != "matcher":
            raise ValueError("Matcher database identity required")
        return self


class Request(Payload):
    revisions: list[UUID] = Field(default_factory=list, max_length=128)
    snapshot_id: UUID | None = None
    enrichment_revision_id: UUID | None = None
    identity: str | None = Field(default=None, pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$", max_length=256)
    stage: Literal["revisions", "snapshots"] = "revisions"
    after: str = Field(default="", max_length=256)
    event_id: UUID | None = None
    rule_version: Literal["matching-1"] = RULE


class Result(Payload):
    count: int = Field(default=0, ge=0)
    revision_id: UUID | None = None
    changed: bool = False


class Decision(Payload):
    component_id: str
    context: str = "host"
    status: Status
    reason: str
    rule_id: str
    data_quality: Literal["complete", "partial", "conflicted"] = "partial"
    adapter: str | None = None
    installed_version: str | None = None
    comparison_version: str | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    conflicts: list[dict[str, Any]] = Field(default_factory=list)


class Evaluation(Payload):
    data_quality: Literal["complete", "partial", "conflicted"] = "partial"
    status: Status
    reason: str
    rule_version: Literal["matching-1"] = RULE
    components: list[Decision]
    coverage: dict[str, Any]
