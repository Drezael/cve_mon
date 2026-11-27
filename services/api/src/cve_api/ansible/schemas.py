"""Bounded connection settings; credentials are write-only."""

import ipaddress
import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class Connection(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    version: int = Field(ge=0, strict=True)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$")
    auth_method: Literal["key", "password"] = "key"
    private_key: SecretStr | None = None
    passphrase: SecretStr | None = None
    password: SecretStr | None = None
    sudo_password: SecretStr | None = None
    use_sudo: Literal[False] = False
    enabled: bool = False
    interval_seconds: int = Field(default=21600, ge=300, le=604800)
    mount_paths: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("host")
    @classmethod
    def valid_host(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value):
                raise ValueError("Hostname or IP address required") from None
        return value

    @field_validator("username")
    @classmethod
    def unprivileged_user(cls, value: str) -> str:
        if value == "root":
            raise ValueError("A dedicated unprivileged inventory user is required")
        return value

    @field_validator("sudo_password")
    @classmethod
    def no_elevation(cls, value: SecretStr | None) -> SecretStr | None:
        if value and value.get_secret_value():
            raise ValueError("Inventory does not use sudo")
        return value

    @field_validator("private_key", "passphrase", "password", "sudo_password")
    @classmethod
    def bounded_secret(cls, value: SecretStr | None) -> SecretStr | None:
        if value and len(value.get_secret_value()) > 32768:
            raise ValueError("Credential too large")
        return value

    @field_validator("mount_paths")
    @classmethod
    def valid_mounts(cls, values: list[str]) -> list[str]:
        if any(
            not p.startswith("/")
            or ".." in p.split("/")
            or len(p) > 1024
            or p in {"/", "/etc", "/proc", "/sys", "/dev", "/run", "/var", "/var/lib"}
            for p in values
        ):
            raise ValueError("Explicit application mount paths required")
        return sorted(set(values))


class ConfirmKey(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprint: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")


class Profile(BaseModel):
    version: int
    host: str
    port: int
    username: str
    auth_method: Literal["key", "password"]
    use_sudo: bool
    enabled: bool
    interval_seconds: int
    next_due: datetime | None
    host_key: str | None
    host_key_confirmed: bool
    mount_paths: list[str]


class RunRead(BaseModel):
    id: UUID
    profile_version: int
    fingerprint: str | None
    action: str
    state: str
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error_code: str | None
    host_key: str | None
    execution_id: str | None
    workflow_id: str | None
    submission_id: UUID | None
    trigger_type: str


class SettingsRead(BaseModel):
    profile: Profile | None
    credentials_configured: bool
    vault_configured: bool
    editable: bool
    runs: list[RunRead]


class Saved(BaseModel):
    saved: Literal[True]


class Confirmed(BaseModel):
    confirmed: Literal[True]


class RunAccepted(BaseModel):
    run_id: UUID
    status: Literal["pending"]
