"""Permanently erase an authorized server and its dependent inventory, findings and work."""

from pathlib import Path
from uuid import UUID, uuid4

from cve_common.database.transactions import transaction
from cve_common.host_control import command
from fastapi import APIRouter, Request, Response

from cve_api.administration.versioning import check
from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.repository import execute, one
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.auth.transactions import security_transaction
from cve_api.authorization.errors import Denied
from cve_api.authorization.principal import load_principal

router = APIRouter(prefix="/api/v1/dashboard/servers", tags=["server-administration"])


@router.delete("/{server_id}", status_code=204)
async def delete_server(server_id: UUID, request: Request) -> Response:
    auth, _ = transport(request)
    csrf = csrf_for(request)
    if auth.administration_database is None:
        raise Denied(503)
    async with security_transaction(auth.administration_database, mutation=False) as session:
        actor, _ = await load_principal(auth, session, request.cookies.get(SESSION_COOKIE), csrf)
        if "server:inventory:manage" not in actor.permissions:
            raise Denied()
        server = await one(
            session,
            "SELECT id,status,created_by,version FROM inventory.servers WHERE id=:id",
            id=server_id,
        )
        if not server or not (actor.administrator or server["created_by"] == actor.user_id):
            raise Denied(404)
        headers = request.headers.getlist("if-match")
        if len(headers) > 1:
            raise Denied(400)
        check(server["version"], headers[0] if headers else None)
        actor_id = actor.user_id
        version = server["version"]
    if request.app.state.deployment_mode == "test":
        async with transaction(auth.administration_database) as session:
            current = await one(
                session,
                "SELECT version FROM inventory.servers WHERE id=:id",
                id=server_id,
            )
            if not current:
                raise Denied(404)
            check(current["version"], headers[0] if headers else None)
            await execute(session, "SET LOCAL statement_timeout='30s'")
            await execute(
                session,
                "SELECT set_config('cve.erasure_expected_version',:version,true)",
                version=str(version),
            )
            await execute(
                session, "SELECT inventory.erase_server(:id,:actor)", id=server_id, actor=actor_id
            )
        return Response(status_code=204)
    try:
        result = await command(
            Path(auth.settings.keyring_file).parent,
            {
                "operation": "erase",
                "server_id": str(server_id),
                "actor_id": str(actor_id),
                "version": version,
                "request_id": str(uuid4()),
            },
        )
    except (OSError, ValueError, TimeoutError):
        raise Denied(503, "erasure_unavailable") from None
    if result.get("status") != 204:
        raise Denied(result.get("status", 503), "erasure_incomplete")
    return Response(status_code=204)
