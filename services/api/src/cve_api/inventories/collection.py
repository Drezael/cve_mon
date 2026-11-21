"""Outbound collector bridge: n8n schedules, mTLS-bound collectors lease and report."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from cve_api.auth.repository import one
from cve_api.auth.transactions import security_transaction
from cve_api.inventories.errors import UploadError
from cve_api.inventories.router import service_for
from cve_api.technical_auth.proxy_identity import proof

router = APIRouter(prefix="/api/v1/inventories/collection", tags=["inventory-collection"])


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alias: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    interval_seconds: int = Field(default=21600, ge=300, le=604800)
    enabled: bool = True
    request_now: bool = False


class Completion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID
    lease_token: UUID
    submission_id: UUID | None = None


async def command(request: Request, action: str, value: Target | Completion | None) -> Any:
    api = service_for(request)
    context = proof(request, api.settings, api.gateway)
    async with api.admission(context.ip, "technical"):
        await api.technical_preflight(context)
        async with security_transaction(api.database, mutation=False) as s:
            source = await api.technical(s, context, touch=True)
            owner = await one(s, "SELECT security.collector_actor(:id) AS id", id=source.identity)
            if not owner or not owner["id"]:
                raise UploadError(403, "collector_owner_required")
            if isinstance(value, Target):
                row = await one(
                    s,
                    "SELECT inventory.collection_register(:p,:alias,:interval,:enabled,:now) AS "
                    "value",
                    p=source.identity,
                    alias=value.alias,
                    interval=value.interval_seconds,
                    enabled=value.enabled,
                    now=value.request_now,
                )
            elif isinstance(value, Completion):
                row = await one(
                    s,
                    "SELECT inventory.collection_finish(:p,:id,:token,:submission) AS value",
                    p=source.identity,
                    id=value.request_id,
                    token=value.lease_token,
                    submission=value.submission_id,
                )
            else:
                row = await one(
                    s, "SELECT inventory.collection_claim(:p) AS value", p=source.identity
                )
            assert row
            if action == "finish" and not row["value"]:
                raise UploadError(409, "collection_lease_expired")
            return {"result": row["value"]}


@router.post("/targets")
async def register(value: Target, request: Request) -> Any:
    return await command(request, "register", value)


@router.post("/claim")
async def claim(request: Request) -> Any:
    return await command(request, "claim", None)


@router.post("/finish")
async def finish(value: Completion, request: Request) -> Any:
    return await command(request, "finish", value)
