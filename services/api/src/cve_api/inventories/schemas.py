"""Admission receipt only; no queued job or completed snapshot is claimed."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class Receipt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    submission_id: UUID
    inventory_id: UUID
    server_id: UUID
    monitoring_id: UUID | None = None
    status: Literal["accepted"]
    duplicate: bool
    source: Literal["ansible_api", "dashboard_file"]
    received_at: datetime
    status_url: str
