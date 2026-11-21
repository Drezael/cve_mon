"""Strict SMTP configuration and a dedicated authenticated credential envelope."""

import json
import re
import secrets
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from cve_common.config.secrets import read_secret

EMAIL = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,63}"
)


class SMTPConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    host: str = Field(default="", max_length=253)
    port: int = Field(default=587, ge=1, le=65535)
    sender: str = Field(default="", max_length=254)
    recipients: list[str] = Field(default_factory=list, max_length=1000)

    @property
    def is_mailhog(self) -> bool:
        """Only the code-owned local capture endpoint permits unencrypted test SMTP."""
        return self.host == "mailhog.cve.test" and self.port == 1025

    @field_validator("host")
    @classmethod
    def hostname(cls, value: str) -> str:
        value = value.strip().lower()
        if value and not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value
        ):
            raise ValueError("SMTP hostname required; URLs and IP addresses are not accepted")
        return value

    @field_validator("sender")
    @classmethod
    def address(cls, value: str) -> str:
        if value:
            local, separator, domain = value.strip().rpartition("@")
            value = local + separator + domain.lower()
        if value and not EMAIL.fullmatch(value):
            raise ValueError("A single sender address is required")
        return value

    @field_validator("recipients")
    @classmethod
    def addresses(cls, value: list[str]) -> list[str]:
        normalized = [cls.address(item) for item in value]
        if any(not item for item in normalized):
            raise ValueError("Explicit recipient addresses are required")
        return sorted(set(normalized))

    @model_validator(mode="after")
    def complete(self) -> "SMTPConfig":
        if self.port == 465:
            raise ValueError("Use a STARTTLS port, usually 587; implicit TLS is not supported")
        if self.enabled and (not self.host or self.host.endswith(".invalid") or not self.sender):
            raise ValueError("Enabled SMTP requires a server and sender")
        return self


class SMTPUpdate(SMTPConfig):
    version: int = Field(ge=0)
    username: str = Field(default="", max_length=256)
    password: SecretStr | None = Field(default=None, max_length=4096)

    @field_validator("username")
    @classmethod
    def user(cls, value: str) -> str:
        if any(c.isspace() or c in "\0:" for c in value):
            raise ValueError("Invalid SMTP username")
        return value

    @field_validator("password")
    @classmethod
    def credential(cls, value: SecretStr | None) -> SecretStr | None:
        if value and any(c.isspace() or c == "\0" for c in value.get_secret_value()):
            raise ValueError("Password must be a single line")
        return value


class PersonalSMTPUpdate(SMTPUpdate):
    mode: Literal["system", "custom"] = "system"

    @model_validator(mode="after")
    def personal(self) -> "PersonalSMTPUpdate":
        if not self.recipients or len(self.recipients) > 20:
            raise ValueError("Between one and twenty recipient addresses are required")
        if self.enabled != (self.mode == "custom"):
            raise ValueError("Custom SMTP must be enabled; system mode uses the central transport")
        return self


class SMTPKeyring:
    def __init__(self, path: Path) -> None:
        value = json.loads(read_secret(path).get_secret_value())
        self.active = value["active"]
        self.keys = {k: bytes.fromhex(v) for k, v in value["keys"].items()}
        if self.active not in self.keys or any(len(v) != 32 for v in self.keys.values()):
            raise ValueError("Invalid SMTP keyring")

    def encrypt(self, identity: UUID, value: dict[str, str]) -> tuple[str, bytes]:
        nonce = secrets.token_bytes(12)
        return self.active, nonce + AESGCM(self.keys[self.active]).encrypt(
            nonce, json.dumps(value).encode(), b"cve:smtp:v1:" + identity.bytes
        )

    def decrypt(self, identity: UUID, key: str, value: bytes) -> dict[str, Any]:
        result: dict[str, Any] = json.loads(
            AESGCM(self.keys[key]).decrypt(value[:12], value[12:], b"cve:smtp:v1:" + identity.bytes)
        )
        return result
