"""Versioned, bounded enrichment and EPSS contracts."""

from datetime import date
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from cve_common.jobs.contracts import Payload
from cve_common.jobs.worker import WorkerSettings
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from pydantic_settings import SettingsConfigDict

RULE: Literal["enrichment-1"] = "enrichment-1"
IDENTITY = r"^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,255}$"


class Configuration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    epss_enabled: bool = False
    epss_batch_size: int = Field(default=10000, ge=1, le=20000)
    rule_version: Literal["enrichment-1"] = RULE
    batch_size: int = Field(default=250, ge=1, le=1000)
    write_batch_size: int = Field(default=32, ge=1, le=256)
    write_flush_seconds: float = Field(default=0.025, ge=0.001, le=1)
    prepared_queue_size: int = Field(default=32, ge=1, le=128)
    prepared_queue_bytes: int = Field(default=67108864, ge=67108864, le=134217728)
    max_source_records: int = Field(default=500, ge=5, le=2000)
    max_source_bytes: int = Field(default=67108864, ge=1048576, le=134217728)
    kev_max_age_hours: int = Field(default=72, ge=1, le=168)
    epss_max_age_days: Literal[2] = 2
    epss_max_download: int = Field(default=67108864, ge=1024, le=268435456)
    epss_max_unpacked: int = Field(default=268435456, ge=1024, le=1073741824)
    epss_max_rows: int = Field(default=1000000, ge=1, le=2000000)
    epss_min_rows: int = Field(default=100000, ge=1, le=2000000)
    epss_min_fraction: float = Field(default=0.9, ge=0.5, le=1)
    epss_timeout: float = Field(default=300, ge=1, le=900)


class Settings(WorkerSettings):
    model_config = SettingsConfigDict(env_prefix="CVE_ENRICHER_")
    service_name: Literal["cve-enricher"] = "cve-enricher"
    concurrency: int = Field(default=1, ge=1, le=4)
    processes: int = Field(default=1, ge=1, le=2)
    batch_size: int = Field(default=1, ge=1, le=2)
    configuration_file: Path
    scratch_directory: Path = Path("/work")
    egress_proof_file: Path
    external_ca_file: Path | None = None

    @model_validator(mode="after")
    def identity(self) -> "Settings":
        if self.database.username != "enricher":
            raise ValueError("Enricher database identity required")
        return self


class Request(Payload):
    identities: list[Annotated[str, StringConstraints(pattern=IDENTITY, max_length=256)]] = Field(
        default_factory=list, max_length=128
    )
    identity: str | None = Field(default=None, pattern=IDENTITY, max_length=256)
    event_id: UUID | None = None
    record_id: UUID | None = None
    rule_version: Literal["enrichment-1"] = RULE
    score_date: date | None = None
    after: str = Field(default="", max_length=256)


class Result(Payload):
    revision_id: UUID | None = None
    dataset_id: UUID | None = None
    changed: bool = False
    count: int = 0


class Event(Payload):
    current_version: int | None = Field(default=None, ge=1)
    identity: str | None = None
    revision_id: UUID | None = None
    dataset_id: UUID | None = None
    changes: list[str] = Field(default_factory=list, max_length=10)
    rule_version: Literal["enrichment-1"] = RULE


class EnrichmentError(ValueError):
    """Fixed code only; never parser diagnostics or source content."""
