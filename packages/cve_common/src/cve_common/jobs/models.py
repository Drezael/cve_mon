"""Immutable reservation snapshots; token+epoch+owner must accompany every mutation."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class Job(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")
    id: UUID
    job_type: str
    payload_version: int
    payload: dict[str, Any]
    correlation_id: UUID
    status: str
    attempts: int
    max_attempts: int
    lease_owner: UUID | None = None
    lease_token: UUID | None = None
    fencing_token: int
    lease_until: datetime | None = None
    execution_deadline: datetime | None = None
    remaining_seconds: float = 300
    cancel_requested: bool = False
    error_code: str | None = None
