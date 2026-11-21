"""ACL-scoped container inventory and software pages from the current server snapshot."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from cve_api.administration.service import rows
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.errors import Denied
from cve_api.authorization.object_access import predicate
from cve_api.authorization.principal import Principal
from cve_api.dashboard.router import service

router = APIRouter(prefix="/api/v1/dashboard", tags=["container-inventory"])


@router.get("/security/servers/{identity}/containers")
async def containers(
    identity: UUID,
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("inventory:read"))],
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
) -> dict[str, Any]:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "inventory:read"
    ) as (s, actor):
        allowed, params = predicate(actor, "inventory:read")
        servers = await rows(
            s,
            "SELECT c.snapshot_id,snap.original_json->'container_software'->>'status' "
            "AS software_status "
            "FROM inventory.servers s "
            "LEFT JOIN inventory.server_current_snapshots c ON c.server_id=s.id "
            "LEFT JOIN inventory.snapshots snap ON snap.id=c.snapshot_id "
            "WHERE s.id=:id AND " + allowed,
            id=identity,
            **params,
        )
        if not servers:
            raise Denied(404)
        snapshot = servers[0]["snapshot_id"]
        values = await rows(
            s,
            "SELECT c.container_id,c.name,c.image_id,c.image_reference,c.state,"
            "coalesce(jsonb_agg(jsonb_build_object('scope',b.scope,'target',b.target,'status',b.status,"
            "'captured_at',b.captured_at,'error_code',b.error_code,'package_count',d.package_count,"
            "'scanner_version',d.document->>'scanner_version')) FILTER(WHERE "
            "b.record_number IS NOT NULL),'[]') AS scans "
            "FROM inventory.containers c LEFT JOIN inventory.container_software b "
            "ON b.snapshot_id=c.snapshot_id AND b.container_id=c.container_id AND "
            "b.image_id=c.image_id "
            "LEFT JOIN inventory.software_bills d ON d.digest=b.bill_digest WHERE "
            "c.snapshot_id=:snapshot "
            "GROUP BY c.container_id,c.name,c.image_id,c.image_reference,c.state ORDER "
            "BY c.name,c.container_id "
            "LIMIT :limit OFFSET :offset",
            snapshot=snapshot,
            limit=limit,
            offset=offset,
        )
        total = await rows(
            s,
            "SELECT count(*) AS n FROM inventory.containers WHERE snapshot_id=:snapshot",
            snapshot=snapshot,
        )
        return {
            "snapshot_id": snapshot,
            "software_status": servers[0]["software_status"] or "not_collected",
            "items": values,
            "total": total[0]["n"],
            "limit": limit,
            "offset": offset,
        }


@router.get("/security/servers/{identity}/container-software")
async def software(
    identity: UUID,
    request: Request,
    _actor: Annotated[Principal, Depends(require_permission("inventory:read"))],
    container_id: str = Query(..., min_length=1, max_length=128),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
) -> dict[str, Any]:
    async with service(request).operation(
        request.cookies.get(SESSION_COOKIE), None, "inventory:read"
    ) as (s, actor):
        allowed, params = predicate(actor, "inventory:read")
        visible = await rows(
            s,
            "SELECT c.snapshot_id FROM inventory.servers s "
            "JOIN inventory.server_current_snapshots c ON c.server_id=s.id WHERE s.id=:id AND "
            + allowed,
            id=identity,
            **params,
        )
        if not visible:
            raise Denied(404)
        base = (
            " FROM inventory.container_software c JOIN inventory.software_bills b ON "
            "b.digest=c.bill_digest "
            "CROSS JOIN LATERAL jsonb_array_elements(b.document->'packages') p "
            "WHERE c.snapshot_id=:snapshot AND c.container_id=:cid"
        )
        args = {"snapshot": visible[0]["snapshot_id"], "cid": container_id}
        values = await rows(
            s,
            "SELECT c.scope,c.target,c.status,b.document->'os' AS os,p AS package"
            + base
            + " ORDER BY p->>'name',p->>'version',c.record_number LIMIT :limit OFFSET :offset",
            **args,
            limit=limit,
            offset=offset,
        )
        total = await rows(s, "SELECT count(*) AS n" + base, **args)
        return {"items": values, "total": total[0]["n"], "limit": limit, "offset": offset}
