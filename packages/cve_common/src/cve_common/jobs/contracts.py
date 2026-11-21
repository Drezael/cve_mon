"""Strict versioned envelopes; payloads never select executable code or a transport."""

import json
import re
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cve_common.logging.correlation import correlation_id

RESERVED = frozenset(
    {
        "password",
        "password_hash",
        "authorization",
        "cookie",
        "token",
        "api_token",
        "secret",
        "private_key",
        "totp_secret",
        "mfa_secret",
        "smtp_password",
        "url",
        "target_url",
        "callback_url",
        "module",
        "class",
        "command",
        "shell",
        "python",
        "transport",
    }
)


def safe_payload(value: dict[str, Any]) -> dict[str, Any]:
    def check(node: Any) -> None:
        if isinstance(node, dict):
            if any(str(k).lower() in RESERVED for k in node):
                raise ValueError("Sensitive or executable payload field")
            for item in node.values():
                check(item)
        elif isinstance(node, list):
            for item in node:
                check(item)

    check(value)
    try:
        encoded = json.dumps(
            value, allow_nan=False, ensure_ascii=False, separators=(",", ":")
        ).encode()
    except (ValueError, TypeError):
        raise ValueError("JSON object required") from None
    if len(encoded) > 16384:
        raise ValueError("Payload too large")
    return value


def correlation_uuid() -> UUID:
    current = correlation_id.get()
    return UUID(current) if current else uuid4()


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class JobEnvelope(Payload):
    job_type: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    payload_version: int = Field(default=1, strict=True, ge=1, le=100)
    payload: dict[str, Any]
    idempotency_key: str = Field(min_length=1, max_length=128)
    scope: str = Field(default="system", min_length=1, max_length=128)
    correlation_id: UUID = Field(default_factory=correlation_uuid)
    priority: int = Field(default=0, strict=True, ge=-100, le=100)
    max_attempts: int = Field(default=3, strict=True, ge=1, le=100)
    scheduled_at: datetime | None = None
    deadline: datetime | None = None
    pending: bool = False

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        return safe_payload(value)

    @field_validator("idempotency_key", "scope")
    @classmethod
    def valid_text(cls, value: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_.:/-]+", value):
            raise ValueError("Invalid key")
        return value

    @field_validator("scheduled_at", "deadline")
    @classmethod
    def aware_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("Timezone required")
        return value
