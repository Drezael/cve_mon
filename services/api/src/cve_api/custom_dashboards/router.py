"""Authenticated personal dashboard CRUD and side-effect-free YAML validation."""

import json
import logging
from datetime import datetime
from typing import Any
from uuid import UUID

import yaml
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.exc import DBAPIError

from cve_api.administration.service import rows
from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.errors import AuthError
from cve_api.auth.repository import execute, one
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.errors import Denied
from cve_api.custom_dashboards.schema import MAX_BYTES, DashboardConfig, Model, parse
from cve_api.findings.service import Findings

router = APIRouter(prefix="/api/v1/dashboard/custom-dashboards", tags=["custom-dashboards"])
FIELDS = "id,title,yaml_source AS yaml,configuration AS config,version,created_at,updated_at"


class Source(Model):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False, hide_input_in_errors=True)
    yaml: str = Field(min_length=1, max_length=MAX_BYTES)

    @field_validator("yaml")
    @classmethod
    def size(cls, value: str) -> str:
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise ValueError("YAML must not exceed 32 KiB")
        return value


class Update(Source):
    version: int = Field(ge=1, strict=True)


class Delete(Model):
    version: int = Field(ge=1, strict=True)


class DashboardSummary(BaseModel):
    id: UUID
    title: str
    description: str
    version: int
    created_at: datetime
    updated_at: datetime
    can_edit: bool = True
    owner_username: str = ""


class DashboardList(BaseModel):
    items: list[DashboardSummary]


class DashboardRead(BaseModel):
    id: UUID
    title: str
    yaml: str
    config: DashboardConfig
    version: int
    created_at: datetime
    updated_at: datetime
    can_edit: bool = True
    owner_username: str = ""


class ValidationRead(BaseModel):
    valid: bool
    config: DashboardConfig | None
    errors: list[str]


def operation(request: Request, mutation: bool = False) -> Any:
    return Findings(transport(request)[0]).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request) if mutation else None, "server:read"
    )


def validated(source: str) -> DashboardConfig:
    try:
        return parse(source)
    except ValueError as error:
        raise HTTPException(422, detail=[{"loc": ["yaml"], "msg": str(error)}]) from None


async def audit(session: Any, actor: UUID, action: str, target: UUID) -> None:
    await execute(
        session,
        (
            "INSERT INTO "
            "security.audit_log(actor_user_id,action,object_type,object_id,outcome,metad"
            "ata) VALUES(:owner,:action,'custom_dashboard',:id,'success','{}'::jsonb)"
        ),
        owner=actor,
        action="custom_dashboard." + action,
        id=str(target),
    )


@router.get("", response_model=DashboardList)
async def listing(request: Request) -> Any:
    async with operation(request) as (s, actor):
        items = await rows(
            s,
            (
                "SELECT d.id,d.title,d.configuration->>'description' AS description,d.version,"
                "d.created_at,d.updated_at,(d.owner_id=:owner) AS can_edit,u.username "
                "AS owner_username "
                "FROM dashboard.custom_dashboards d JOIN security.users u ON u.id=d.owner_id "
                "WHERE d.owner_id=:owner OR EXISTS(SELECT 1 FROM "
                "dashboard.custom_dashboard_shares sh "
                "WHERE sh.dashboard_id=d.id AND sh.user_id=:owner) ORDER BY lower(d.title),d.id"
            ),
            owner=actor.user_id,
        )
        return {"items": items}


@router.post("/validate", response_model=ValidationRead)
async def validate(request: Request, body: Source) -> Any:
    async with operation(request, True):
        try:
            config = parse(body.yaml)
        except ValueError as error:
            return {"valid": False, "config": None, "errors": [str(error)]}
        return {"valid": True, "config": config.model_dump(mode="json"), "errors": []}


@router.get("/{identity}", response_model=DashboardRead)
async def detail(identity: UUID, request: Request) -> Any:
    async with operation(request) as (s, actor):
        result = await one(
            s,
            "SELECT d.id,d.title,d.yaml_source AS yaml,d.configuration AS config,d.version,"
            "d.created_at,d.updated_at,(d.owner_id=:owner) AS can_edit,u.username "
            "AS owner_username "
            "FROM dashboard.custom_dashboards d JOIN security.users u ON u.id=d.owner_id "
            "WHERE d.id=:id AND (d.owner_id=:owner OR EXISTS(SELECT 1 FROM "
            "dashboard.custom_dashboard_shares sh "
            "WHERE sh.dashboard_id=d.id AND sh.user_id=:owner))",
            id=identity,
            owner=actor.user_id,
        )
        if not result:
            raise Denied(404)
        return result


@router.post("", status_code=201, response_model=DashboardRead)
async def create(request: Request, body: Source) -> Any:
    async with operation(request, True) as (s, actor):
        config = validated(body.yaml)
        await execute(
            s, "SELECT pg_advisory_xact_lock(hashtextextended(:owner,72))", owner=str(actor.user_id)
        )
        count = await one(
            s,
            "SELECT count(*) n FROM dashboard.custom_dashboards WHERE owner_id=:owner",
            owner=actor.user_id,
        )
        if count and count["n"] >= 50:
            raise Denied(422, "dashboard_limit")
        result = await one(
            s,
            (
                "INSERT INTO "
                "dashboard.custom_dashboards(owner_id,title,yaml_source,configuration) "
                "VALUES(:owner,:title,:yaml,CAST(:config AS jsonb)) RETURNING "
            )
            + FIELDS,
            owner=actor.user_id,
            title=config.title,
            yaml=body.yaml,
            config=json.dumps(config.model_dump(mode="json")),
        )
        assert result
        await audit(s, actor.user_id, "created", result["id"])
        return result


@router.put("/{identity}", response_model=DashboardRead)
async def update(identity: UUID, request: Request, body: Update) -> Any:
    async with operation(request, True) as (s, actor):
        config = validated(body.yaml)
        current = await one(
            s,
            (
                "SELECT version FROM dashboard.custom_dashboards WHERE id=:id AND "
                "owner_id=:owner FOR UPDATE"
            ),
            id=identity,
            owner=actor.user_id,
        )
        if not current:
            raise Denied(404)
        if current["version"] != body.version:
            raise Denied(409, "stale_version")
        result = await one(
            s,
            (
                "UPDATE dashboard.custom_dashboards SET "
                "title=:title,yaml_source=:yaml,configuration=CAST(:config AS "
                "jsonb),version=version+1,updated_at=clock_timestamp() WHERE id=:id AND "
                "owner_id=:owner RETURNING "
            )
            + FIELDS,
            id=identity,
            owner=actor.user_id,
            title=config.title,
            yaml=body.yaml,
            config=json.dumps(config.model_dump(mode="json")),
        )
        assert result
        await audit(s, actor.user_id, "updated", identity)
        return result


@router.delete("/{identity}")
async def delete(identity: UUID, request: Request, body: Delete) -> Any:
    try:
        async with operation(request, True) as (s, actor):
            current = await one(
                s,
                (
                    "SELECT version FROM dashboard.custom_dashboards WHERE id=:id AND "
                    "owner_id=:owner FOR UPDATE"
                ),
                id=identity,
                owner=actor.user_id,
            )
            if not current:
                raise Denied(404)
            if current["version"] != body.version:
                raise Denied(409, "stale_version")
            await execute(
                s,
                "DELETE FROM dashboard.custom_dashboards WHERE id=:id AND owner_id=:owner",
                id=identity,
                owner=actor.user_id,
            )
            await audit(s, actor.user_id, "deleted", identity)
            return None
    except (Denied, AuthError, DBAPIError) as error:
        reason = (
            error.reason
            if isinstance(error, Denied)
            else (
                "authentication_failed" if isinstance(error, AuthError) else "database_unavailable"
            )
        )
        logging.getLogger("cve.custom_dashboards").warning(
            "request",
            extra={
                "diagnostic_code": "dashboard_delete_" + reason,
                "status": getattr(error, "status", 503),
            },
        )
        raise


class Shares(Model):
    version: int = Field(ge=1)
    usernames: list[str] = Field(max_length=50)


class Copy(Source):
    title: str = Field(min_length=1, max_length=128)


@router.get("/{identity}/shares")
async def share_list(identity: UUID, request: Request) -> Any:
    async with operation(request) as (s, actor):
        board = await one(
            s,
            "SELECT version FROM dashboard.custom_dashboards WHERE id=:id AND owner_id=:owner",
            id=identity,
            owner=actor.user_id,
        )
        if not board:
            raise Denied(404)
        recipients = await rows(
            s,
            "SELECT u.username FROM dashboard.custom_dashboard_shares sh JOIN "
            "security.users u ON u.id=sh.user_id WHERE sh.dashboard_id=:id ORDER "
            "BY u.username",
            id=identity,
        )
        return {"version": board["version"], "usernames": [r["username"] for r in recipients]}


@router.put("/{identity}/shares")
async def share(identity: UUID, request: Request, body: Shares) -> Any:
    async with operation(request, True) as (s, actor):
        board = await one(
            s,
            "SELECT version FROM dashboard.custom_dashboards WHERE id=:id AND "
            "owner_id=:owner FOR UPDATE",
            id=identity,
            owner=actor.user_id,
        )
        if not board:
            raise Denied(404)
        if board["version"] != body.version:
            raise Denied(409)
        targets = []
        for name in set(name.strip().casefold() for name in body.usernames if name.strip()):
            target = await one(
                s,
                "SELECT id FROM security.users WHERE lower(username)=:name AND status='active'",
                name=name,
            )
            if not target:
                raise HTTPException(422, detail="Unknown or inactive username")
            if target["id"] != actor.user_id:
                targets.append(target["id"])
        await execute(
            s, "DELETE FROM dashboard.custom_dashboard_shares WHERE dashboard_id=:id", id=identity
        )
        for target in targets:
            await execute(
                s,
                "INSERT INTO dashboard.custom_dashboard_shares(dashboard_id,user_id) "
                "VALUES(:id,:user)",
                id=identity,
                user=target,
            )
        await execute(
            s,
            "UPDATE dashboard.custom_dashboards SET "
            "version=version+1,updated_at=clock_timestamp() WHERE id=:id",
            id=identity,
        )
        await audit(s, actor.user_id, "shared", identity)
        return {"version": board["version"] + 1, "usernames": body.usernames}


@router.post("/{identity}/copy", status_code=201, response_model=DashboardRead)
async def copy(identity: UUID, request: Request, body: Copy) -> Any:
    # Recheck the source share before creating an independent copy. Update/delete remain owner-only.
    await detail(identity, request)
    config = validated(body.yaml)
    validated_config = DashboardConfig.model_validate(
        config.model_dump() | {"title": body.title.strip()}
    )
    node = yaml.compose(body.yaml)
    assert isinstance(node, yaml.MappingNode)
    title_node = next(value for key, value in node.value if key.value == "title")
    old = body.yaml[title_node.start_mark.index : title_node.end_mark.index]
    replacement = json.dumps(validated_config.title, ensure_ascii=False) + (
        "\n" if old.endswith("\n") else ""
    )
    source = (
        body.yaml[: title_node.start_mark.index]
        + replacement
        + body.yaml[title_node.end_mark.index :]
    )
    return await create(request, Source(yaml=source))
