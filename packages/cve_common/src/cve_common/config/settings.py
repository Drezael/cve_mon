"""Explicit settings > service environment > nonsecret defaults; no dotenv/secret fallbacks."""

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

RUNTIME_ROLES = frozenset(
    {
        "api_reader",
        "api_ingest",
        "api_security",
        "dashboard_admin",
        "inventory_processor",
        "importer",
        "enricher",
        "matcher",
        "findings_writer",
        "reporter",
        "event_dispatcher",
        "notification",
        "status_probe",
        "dashboard_preferences",
        "ansible_worker",
    }
)


class DatabaseSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True, frozen=True)
    host: str
    port: int = Field(default=5432, ge=1, le=65535)
    database: Literal["cve_monitoring"] = "cve_monitoring"
    username: str
    password_file: Path = Field(repr=False)
    ca_file: Path
    hostaddr: str | None = None
    pool_size: int = Field(default=3, ge=1, le=10)
    max_overflow: int = Field(default=0, ge=0, le=5)
    pool_timeout: float = Field(default=2, gt=0, le=10)
    connect_timeout: int = Field(default=2, ge=1, le=10)
    statement_timeout_ms: int = Field(default=2000, ge=10, le=30000)

    @field_validator("host")
    @classmethod
    def valid_host(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value):
            raise ValueError("Invalid database hostname")
        return value

    @field_validator("hostaddr")
    @classmethod
    def valid_address(cls, value: str | None) -> str | None:
        if value is not None:
            import ipaddress

            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ValueError("Invalid database address") from None
        return value

    @field_validator("username")
    @classmethod
    def runtime_identity(cls, value: str) -> str:
        if value not in RUNTIME_ROLES:
            raise ValueError("Explicit runtime database identity required")
        return value


class ServiceSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CVE_SERVICE_",
        env_nested_delimiter="__",
        extra="forbid",
        hide_input_in_errors=True,
        frozen=True,
    )
    service_name: str
    app_env: Literal["development", "test", "production"]
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    http_port: int = Field(default=8000, ge=1024, le=65535)
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    ready_timeout: float = Field(default=1, gt=0, le=5)
    database: DatabaseSettings | None = None

    @field_validator("service_name")
    @classmethod
    def valid_service(cls, value: str) -> str:
        if not re.fullmatch(r"cve-[a-z][a-z0-9-]{0,46}", value):
            raise ValueError("Invalid service name")
        return value

    @field_validator("allowed_hosts")
    @classmethod
    def valid_hosts(cls, values: list[str]) -> list[str]:
        if not values or any(not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", v) for v in values):
            raise ValueError("Explicit hostnames required")
        return values

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return init_settings, env_settings
