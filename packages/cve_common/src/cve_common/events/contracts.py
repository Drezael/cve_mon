"""Versioned data-only event envelope; timestamps and fingerprints are database-bound."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from cve_common.jobs.contracts import Payload, correlation_uuid, safe_payload


class EventEnvelope(Payload):
    event_id: UUID = Field(default_factory=uuid4)
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    schema_version: int = Field(default=1, strict=True, ge=1, le=100)
    source: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    aggregate_type: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    aggregate_id: str = Field(min_length=1, max_length=128)
    aggregate_version: int = Field(strict=True, ge=1, le=9223372036854775807)
    occurred_at: datetime | None = None
    correlation_id: UUID = Field(default_factory=correlation_uuid)
    idempotency_key: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]

    @field_validator("payload")
    @classmethod
    def valid_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        return safe_payload(value)

    @field_validator("occurred_at")
    @classmethod
    def valid_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("Timezone required")
        return value
