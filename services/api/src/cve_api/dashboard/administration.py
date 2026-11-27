"""Read selectors revalidate existing rights; preview uses the actual finite template engine."""

from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from cve_common.database.queries import one, rows
from cve_notification.contracts import Template
from cve_notification.rendering import message
from fastapi import APIRouter, Depends, Query, Request

from cve_api.auth.dependencies import csrf_for
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.errors import Denied
from cve_api.authorization.object_access import predicate
from cve_api.authorization.policies import target_allowed
from cve_api.authorization.principal import Principal
from cve_api.dashboard.router import service
from cve_api.inventories.parser import schema
from cve_api.inventories.router import service_for

router = APIRouter(prefix="/api/v1/dashboard/administration", tags=["dashboard-administration"])


@router.get("/upload-options")
async def upload_options(
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("server:inventory:manage"))],
    search: str = Query("", max_length=128),
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "server:inventory:manage"
    ) as (s, actor):
        scope = (
            "true"
            if actor.administrator
            else (
                "(s.created_by=:actor OR EXISTS(SELECT 1 FROM security.user_server_access a "
                "WHERE a.server_id=s.id AND a.user_id=:actor AND a.can_upload))"
            )
        )
        params = {} if actor.administrator else {"actor": actor.user_id}
        where = (
            "s.status='active' AND " + scope + " AND strpos(lower(s.display_name),lower(:search))>0"
        )
        values = await rows(
            s,
            "SELECT s.id,s.display_name FROM inventory.servers s WHERE "
            + where
            + " ORDER BY lower(s.display_name),s.id LIMIT :limit OFFSET :offset",
            **params,
            search=search,
            limit=limit,
            offset=offset,
        )
        count = await one(
            s,
            "SELECT count(*) AS n FROM inventory.servers s WHERE " + where,
            **params,
            search=search,
        )
        assert count
        return {
            "items": values,
            "total": count["n"],
            "limit": limit,
            "offset": offset,
            "max_bytes": service_for(request).settings.max_bytes,
            "schema_versions": ["1.0", "1.1", "1.2", "1.3"],
        }


@router.get("/inventory-schema/{version}")
async def inventory_schema(
    version: Literal["1.0", "1.1", "1.2", "1.3"],
    _actor: Annotated[Principal, Depends(require_permission("server:inventory:manage"))],
) -> Any:
    return schema(version)


@router.get("/uploads/{identity}")
async def upload_status(identity: UUID, request: Request) -> Any:
    receipt = await service_for(request).status_dashboard(
        request.cookies.get(SESSION_COOKIE), identity
    )
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "inventory:read"
    ) as (s, actor):
        allowed, params = predicate(actor, "inventory:read")
        result = await one(
            s,
            (
                "SELECT p.status,p.snapshot_id,p.started_at,p.finis"
                "hed_at,p.error_code,p.attempts FROM inventory.subm"
                "issions q JOIN inventory.servers s ON s.id=q.serve"
                "r_id LEFT JOIN inventory.processing_status p ON p."
                "submission_id=q.id WHERE q.id=:id AND q.source_ide"
                "ntity=:user AND q.source='dashboard_file' AND "
            )
            + allowed,
            **params,
            id=identity,
            user=actor.user_id,
        )
        if result is None:
            raise Denied(404)
        return {
            "receipt": receipt,
            "processing": result if result["status"] else {"status": "accepted"},
        }


@router.get("/findings/{identity}/assignees")
async def assignees(
    identity: UUID,
    request: Request,
    search: str = Query("", max_length=128),
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
) -> Any:
    api = service(request)
    async with api.operation(request.cookies.get(SESSION_COOKIE), None, "finding:update") as (
        s,
        actor,
    ):
        finding = await api.visible(s, actor, identity, "finding:update")
        where = (
            "findings.assignee_eligible(u.id,:server) AND strpo"
            "s(lower(u.display_name),lower(:search))>0"
        )
        values = await rows(
            s,
            "SELECT u.id,u.display_name FROM security.users u WHERE "
            + where
            + " ORDER BY u.display_name,u.id LIMIT :limit OFFSET :offset",
            server=finding["server_id"],
            search=search,
            limit=limit,
            offset=offset,
        )
        count = await one(
            s,
            "SELECT count(*) n FROM security.users u WHERE " + where,
            server=finding["server_id"],
            search=search,
        )
        assert count
        return {"items": values, "total": count["n"], "limit": limit, "offset": offset}


@router.get("/users/{identity}/roles")
async def user_roles(identity: UUID, request: Request) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "user:read"
    ) as (s, actor):
        await target_allowed(s, actor, identity)
        return {
            "items": await rows(
                s,
                (
                    "SELECT r.id,r.name,r.code FROM security.user_roles"
                    " ur JOIN security.roles r ON r.id=ur.role_id WHERE"
                    " ur.user_id=:id ORDER BY r.code"
                ),
                id=identity,
            )
        }


@router.get("/audit")
async def audit(
    request: Request,
    action: str = Query("", max_length=128),
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "audit:read"
    ) as (s, actor):
        where = "(:admin OR actor_user_id=:actor) AND strpos(action,:action)>0"
        params = {"admin": actor.administrator, "actor": actor.user_id, "action": action}
        values = await rows(
            s,
            "SELECT * FROM dashboard.administration_audit WHERE "
            + where
            + " ORDER BY occurred_at DESC,id LIMIT :limit OFFSET :offset",
            **params,
            limit=limit,
            offset=offset,
        )
        count = await one(
            s, "SELECT count(*) n FROM dashboard.administration_audit WHERE " + where, **params
        )
        assert count
        return {"items": values, "total": count["n"], "limit": limit, "offset": offset}


@router.post("/templates/preview")
async def preview(body: Template, request: Request) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), "notification:template:read"
    ):
        result = message(
            body,
            notification_id=str(uuid4()),
            sender="preview@example.test",
            recipient="preview@example.test",
            base="https://dashboard.example.test",
            items=["Kontrollierte Vorschau: CVE-2026-1234, Beispielserver, Priorität hoch"],
        )
        plain = result.get_body(preferencelist=("plain",))
        html_part = result.get_body(preferencelist=("html",))
        assert plain is not None and html_part is not None
        return {
            "subject": str(result["Subject"]),
            "text": plain.get_content(),
            "html": html_part.get_content(),
        }


@router.get("/uploads")
async def find_upload(request: Request, inventory_id: UUID) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "inventory:read"
    ) as (s, actor):
        allowed, params = predicate(actor, "inventory:read")
        return {
            "items": await rows(
                s,
                (
                    "SELECT q.id AS submission_id,q.inventory_id,q.rece"
                    "ived_at FROM inventory.submissions q JOIN inventor"
                    "y.servers s ON s.id=q.server_id WHERE q.inventory_"
                    "id=:id AND q.source_identity=:user AND q.source='d"
                    "ashboard_file' AND "
                )
                + allowed
                + " ORDER BY q.received_at DESC LIMIT 1",
                **params,
                id=inventory_id,
                user=actor.user_id,
            )
        }


@router.get("/notification-history/{kind}/{identity}")
async def notification_history(
    kind: Literal["rules", "templates"],
    identity: str,
    request: Request,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
) -> Any:
    action = "notification:rule:read" if kind == "rules" else "notification:template:read"
    async with service(request).operation(request.cookies.get(SESSION_COOKIE), None, action) as (
        s,
        _actor,
    ):
        table = (
            "automation.notification_rules"
            if kind == "rules"
            else "automation.notification_templates"
        )
        key = "rule_key::text" if kind == "rules" else "name"
        if len(identity) > 64:
            raise Denied(422)
        values = await rows(
            s,
            "SELECT * FROM "
            + table
            + " WHERE "
            + key
            + "=:id ORDER BY version DESC LIMIT :limit OFFSET :offset",
            id=identity,
            limit=limit,
            offset=offset,
        )
        count = await one(
            s, "SELECT count(*) n FROM " + table + " WHERE " + key + "=:id", id=identity
        )
        assert count
        return {"items": values, "total": count["n"], "limit": limit, "offset": offset}


@router.get("/notification-rules")
async def notification_rules(
    request: Request, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0, le=100000)
) -> Any:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, ("notification:rule:read")
    ) as (s, _actor):
        values = await rows(
            s,
            (
                "SELECT * FROM (SELECT DISTINCT ON(rule_key) * FROM"
                " automation.notification_rules ORDER BY rule_key,v"
                "ersion DESC) r ORDER BY created_at DESC,id LIMIT :"
                "limit OFFSET :offset"
            ),
            limit=limit,
            offset=offset,
        )
        count = await one(s, "SELECT count(DISTINCT rule_key) n FROM automation.notification_rules")
        assert count
        return {"items": values, "total": count["n"], "limit": limit, "offset": offset}
