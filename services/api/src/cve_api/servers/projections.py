"""Explicit safe response projections; no technical credentials or user contact fields."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from cve_api.servers.schemas import Criticality, Exposure


class ServerRead(BaseModel):
    id: UUID
    display_name: str
    description: str | None
    environment: str | None
    criticality: Criticality
    exposure: Exposure
    status: str
    primary_group_id: UUID | None
    display_order: int
    created_at: datetime
    updated_at: datetime
    archived_at: datetime | None
    version: int


class GroupRead(BaseModel):
    id: UUID
    name: str
    description: str | None
    status: str
    sort_order: int
    created_at: datetime
    updated_at: datetime
    archived_at: datetime | None
    version: int


class VisibleGroup(GroupRead):
    visible_servers: int


class ServerPage(BaseModel):
    items: list[ServerRead]
    total: int
    limit: int
    offset: int


class GroupPage(BaseModel):
    items: list[VisibleGroup]
    total: int
    limit: int
    offset: int
