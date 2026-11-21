"""Closed operator contracts; downloaded data never chooses an executable or arbitrary host."""

from pathlib import Path
from typing import Literal
from uuid import UUID

from cve_common.jobs.contracts import Payload
from cve_common.jobs.worker import WorkerSettings
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_settings import SettingsConfigDict

Source = Literal["cve_list", "nvd", "cisa_kev", "ubuntu", "osv"]
SOURCES: tuple[Source, ...] = ("cve_list", "nvd", "cisa_kev", "ubuntu", "osv")
ECOSYSTEMS = frozenset(
    {
        "PyPI",
        "npm",
        "Go",
        "Maven",
        "crates.io",
        "RubyGems",
        "Debian",
        "Ubuntu",
        "Alpine",
        "NuGet",
        "Packagist",
        "Hex",
        "Pub",
        "Linux",
        "Rocky Linux",
        "AlmaLinux",
    }
)


class Configuration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    enabled: list[Source] = Field(default=["cve_list"])
    git_validation_workers: int = Field(default=2, ge=1, le=4)
    cve_list_transport: Literal["git", "release"] = "git"
    epss_enabled: bool = False
    enrichment_batch_size: int = Field(default=32, ge=1, le=128)
    osv_ecosystems: list[str] = Field(default_factory=list, max_length=16)
    max_download: int = Field(default=1073741824, ge=1024, le=4294967296)
    max_json: int = Field(default=16777216, ge=1024, le=67108864)
    max_unpacked: int = Field(default=17179869184, ge=1024, le=68719476736)
    max_files: int = Field(default=1000000, ge=1, le=2000000)
    max_ratio: int = Field(default=1000, ge=2, le=2000)
    batch_size: int = Field(default=250, ge=1, le=1000)
    page_size: int = Field(default=1000, ge=1, le=2000)
    overlap_hours: int = Field(default=24, ge=1, le=168)
    minimum_delay: float = Field(default=0.2, ge=0, le=60)
    nvd_delay: float = Field(default=6.5, ge=0.65, le=60)
    request_attempts: int = Field(default=3, ge=1, le=3)
    max_retry_delay: float = Field(default=120, ge=1, le=900)
    download_seconds: float = Field(default=900, ge=1, le=1800)
    scratch_limit: int = Field(default=8589934592, ge=1048576, le=68719476736)
    kev_minimum_fraction: float = Field(default=0.5, ge=0, le=1)

    @model_validator(mode="after")
    def ecosystems(self) -> "Configuration":
        if (
            len(set(self.enabled)) != len(self.enabled)
            or len(set(self.osv_ecosystems)) != len(self.osv_ecosystems)
            or not set(self.osv_ecosystems) <= ECOSYSTEMS
        ):
            raise ValueError("Explicit, unique registered sources and ecosystems required")
        return self


class ImportSettings(WorkerSettings):
    model_config = SettingsConfigDict(env_prefix="CVE_IMPORTER_")
    service_name: Literal["cve-importer"] = "cve-importer"
    concurrency: int = Field(default=1, ge=1, le=2)
    batch_size: int = Field(default=1, ge=1, le=2)
    configuration_file: Path
    scratch_directory: Path = Path("/work")
    egress_proof_file: Path
    nvd_key_file: Path | None = Field(default=None, repr=False)
    external_ca_file: Path | None = None

    @model_validator(mode="after")
    def identity(self) -> "ImportSettings":
        if self.database.username != "importer":
            raise ValueError("Importer database identity required")
        return self


class Request(Payload):
    run_id: UUID


class Result(Payload):
    run_id: UUID
    status: Literal["completed", "partial"]


class ImportFailure(ValueError):
    """Fixed public code; no response text, URLs, credentials or parser diagnostics."""
