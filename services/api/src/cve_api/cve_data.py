"""CVE source freshness and fixed, durable background updates from the dashboard."""

import json
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID

from cve_common.database.queries import one
from cve_common.matching_support import VERSION_SUPPORT
from cve_importer.contracts import Configuration
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi import Path as ApiPath
from pydantic import BaseModel, Field, ValidationError

from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.errors import Denied
from cve_api.authorization.principal import Principal
from cve_api.findings.service import Findings

router = APIRouter(prefix="/api/v1/dashboard/cve-data", tags=["cve-data"])


class SourceStatus(BaseModel):
    id: str
    name: str
    record_count: int
    last_success_at: datetime | None
    last_attempt_at: datetime | None
    status: str
    updating: bool
    enabled: bool
    configured: bool
    git_commit: str | None = None
    error_count: int = Field(default=0, ge=0)


class PipelineStatus(BaseModel):
    indexed_records: int = Field(default=0, ge=0)
    processed_records: int = Field(ge=0)
    processed_cves: int = Field(ge=0)
    processed_advisories: int = Field(ge=0)
    waiting: int = Field(ge=0)
    retrying: int = Field(ge=0)
    running: int = Field(ge=0)
    outstanding: int = Field(ge=0)
    completed_jobs: int = Field(ge=0)
    failed_jobs: int = Field(ge=0)


class QueueStatus(BaseModel):
    pending: int
    processing: int
    failed: int
    position: int | None
    id: UUID | None
    state: str | None


class DataStatus(BaseModel):
    version_support: dict[str, str | None] = Field(default_factory=lambda: dict(VERSION_SUPPORT))
    queue: QueueStatus | None = None
    pipeline: PipelineStatus
    cve_count: int
    record_count: int
    last_success_at: datetime | None
    updating: bool
    can_update: bool
    sources: list[SourceStatus]


class UpdateJob(BaseModel):
    source: str
    id: UUID


class UpdateResult(BaseModel):
    jobs: list[UpdateJob]


class DocumentSummary(BaseModel):
    identity: str
    source_revision_id: UUID
    document_present: bool
    source_status: str
    published_at: datetime | None
    modified_at: datetime | None
    git_commit: str | None
    git_path: str | None
    git_blob_oid: str | None


class DocumentPage(BaseModel):
    items: list[DocumentSummary]
    next_after: str | None


class NativeDocument(DocumentSummary):
    document: dict[str, Any]


@router.get("/documents", response_model=DocumentPage)
async def documents(
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("cve:read"))],
    after: str = Query("", max_length=256, pattern=r"^(?:CVE-[0-9]{4}-[0-9]{4,})?$"),
    limit: int = Query(25, ge=1, le=100),
) -> Any:
    auth, _ = transport(request)
    async with Findings(auth).operation(request.cookies.get(SESSION_COOKIE), None, "cve:read") as (
        s,
        _,
    ):
        from sqlalchemy import text

        rows = list(
            (
                await s.execute(
                    text("""
SELECT identity,source_revision_id,document_present,source_status,published_at,modified_at,
 git_commit,git_path,git_blob_oid FROM cve.v5_current_documents
WHERE identity>:after ORDER BY identity LIMIT :limit
"""),
                    {"after": after, "limit": limit + 1},
                )
            ).mappings()
        )
        return {
            "items": rows[:limit],
            "next_after": rows[limit - 1]["identity"] if len(rows) > limit else None,
        }


@router.get("/documents/{identity}", response_model=NativeDocument)
async def document(
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("cve:read"))],
    identity: str = ApiPath(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$", max_length=256),
) -> Any:
    auth, _ = transport(request)
    async with Findings(auth).operation(request.cookies.get(SESSION_COOKIE), None, "cve:read") as (
        s,
        _,
    ):
        row = await one(s, "SELECT * FROM cve.v5_current_documents WHERE identity=:id", id=identity)
        if row is None:
            raise HTTPException(404, "CVE not found")
        return row


def configuration(path: Path | None) -> Configuration | None:
    try:
        if path is None or path.is_symlink() or path.stat().st_size > 16384:
            return None
        return Configuration.model_validate_json(path.read_bytes())
    except (OSError, ValueError, ValidationError):
        return None


@router.get("", response_model=DataStatus)
async def status(
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("cve:read"))],
) -> Any:
    auth, _ = transport(request)
    cfg = configuration(request.app.state.cve_configuration_file)
    async with Findings(auth).operation(request.cookies.get(SESSION_COOKIE), None, "cve:read") as (
        s,
        actor,
    ):
        row = await request.app.state.cve_data_cache.get(s)
        value = row["value"]
        sources = [*value["sources"], value["epss"]]
        for source in sources:
            source["configured"] = cfg is not None and (
                source["id"] == "epss"
                and cfg.epss_enabled
                or source["id"] in cfg.enabled
                and (source["id"] != "osv" or bool(cfg.osv_ecosystems))
            )
        # Show only selected sources; disabled adapters are not part of this collection.
        sources = [
            source
            for source in sources
            if (
                cfg is not None
                and (source["id"] in cfg.enabled or source["id"] == "epss" and cfg.epss_enabled)
            )
            or (cfg is None and source["id"] != "epss" and source["enabled"])
        ]
        dates = [
            datetime.fromisoformat(i["last_success_at"]) for i in sources if i["last_success_at"]
        ]
        queued = await one(
            s,
            """
WITH commands AS (SELECT * FROM automation.n8n_queue
 WHERE kind='command' AND message_type='cve.refresh'),
 next AS (SELECT * FROM commands WHERE state IN ('pending','processing') ORDER BY sequence LIMIT 1)
SELECT (SELECT count(*) FROM commands WHERE state='pending') AS pending,
 (SELECT count(*) FROM commands WHERE state='processing') AS processing,
 (SELECT count(*) FROM commands WHERE state='failed') AS failed,
 (SELECT id FROM next) AS id,(SELECT state FROM next) AS state,
 (SELECT count(*) FROM automation.n8n_queue q,next
 WHERE q.state IN ('pending','processing') AND q.sequence<=next.sequence) AS position
""",
        )
        assert queued
        if queued["id"] is None:
            queued["position"] = None
        return {
            "queue": queued,
            "pipeline": row["pipeline"],
            "cve_count": row["pipeline"]["processed_cves"],
            "record_count": value["record_count"],
            "last_success_at": max(dates) if dates else None,
            "updating": any(i["updating"] for i in sources)
            or bool(queued["pending"] or queued["processing"]),
            "can_update": cfg is not None
            and actor.administrator
            and "cve:update" in actor.permissions,
            "sources": sources,
        }


@router.post("/refresh", response_model=UpdateResult, status_code=202)
async def refresh(
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("cve:update"))],
    key: Annotated[UUID, Header(alias="Idempotency-Key")],
) -> Any:
    auth, _ = transport(request)
    async with Findings(auth).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "cve:update"
    ) as (s, actor):
        if not actor.administrator:
            raise Denied(403, "admin_role_required")
        cfg = configuration(request.app.state.cve_configuration_file)
        if cfg is None:
            raise HTTPException(503, "Source configuration unavailable")
        row = await one(
            s,
            "SELECT cve.dashboard_request_update(:key,:actor,CAST(:cfg AS jsonb)) AS value",
            key=key,
            actor=actor.user_id,
            cfg=json.dumps(cfg.model_dump(mode="json")),
        )
        assert row is not None
        result = {"jobs": row["value"]}
    request.app.state.cve_data_cache.invalidate()
    return result
