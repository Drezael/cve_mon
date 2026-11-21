from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel


class Overview(BaseModel):
    generated_at: datetime
    scope: str
    active_servers: int
    servers_affected: int | None
    open_findings: int | None
    critical: int | None
    high: int | None
    potentially_affected: int | None
    unknown: int | None
    overdue: int | None
    kev: int | None
    priorities: dict[str, int]
    lifecycle: dict[str, int]
    technical: dict[str, int]
    kev_priorities: dict[str, int]
    inventory: dict[str, int | None]
    matching: dict[str, int]
    finding_data_available: bool
    inventory_data_available: bool


class TrendPoint(BaseModel):
    day: str
    detected: int
    resolved: int
    reopened: int
    closed: int


class Trends(BaseModel):
    generated_at: datetime
    timezone: str
    days: int
    items: list[TrendPoint]


class ServerSummary(BaseModel):
    version: int = 1
    can_delete: bool = False
    can_edit: bool = False
    can_scan: bool = False
    id: UUID
    display_name: str
    status: str
    primary_group_id: UUID | None
    display_order: int
    environment: str | None
    criticality: str
    inventory: dict[str, Any] | None
    matching: dict[str, Any] | None
    open_findings: int | None
    highest_priority: str | None
    groups: list[dict[str, Any]]


class ServerSummaries(BaseModel):
    items: list[ServerSummary]
    total: int
    limit: int
    offset: int


class Context(BaseModel):
    finding_id: UUID
    snapshot_id: UUID
    enrichment_revision_id: UUID
    rule_version: str
    matched_at: datetime
    status: str
    coverage: dict[str, Any]
    components: list[dict[str, Any]] = []
    data_quality: str | None
