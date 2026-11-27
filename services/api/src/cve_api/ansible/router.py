"""Owner-scoped connection settings and manual runs; n8n still authorizes every execution."""

import base64
import hashlib
import json
from typing import Any, Literal
from uuid import UUID

from cve_common.user_vault import FORMAT, update_credentials
from fastapi import APIRouter, Request
from sqlalchemy import text

from cve_api.administration.service import rows
from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.repository import one
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.auth.transactions import security_transaction
from cve_api.authorization.errors import Denied
from cve_api.authorization.principal import Principal, load_principal

from .audit import audit
from .schemas import Confirmed, ConfirmKey, Connection, RunAccepted, Saved, SettingsRead
from .vault import keyring

router = APIRouter(prefix="/api/v1/dashboard/servers", tags=["ansible-collection"])
SECRET_FIELDS = ("private_key", "passphrase", "password", "sudo_password")


async def owned(session: Any, actor: Principal, server: UUID) -> None:
    if "server:inventory:manage" not in actor.permissions:
        raise Denied()
    value = await one(
        session,
        "SELECT created_by FROM inventory.servers WHERE id=:id AND status='active'",
        id=server,
    )
    if not value or not (actor.administrator or value["created_by"] == actor.user_id):
        raise Denied(404)


@router.get("/{server}/ansible", response_model=SettingsRead)
async def settings(server: UUID, request: Request) -> dict[str, Any]:
    auth, _ = transport(request)
    async with security_transaction(auth.database, mutation=False) as s:
        actor, _ = await load_principal(auth, s, request.cookies.get(SESSION_COOKIE))
        await owned(s, actor, server)
        profile = await one(
            s,
            "SELECT host,port,username,auth_method,use_sudo,enabled,interval_seconds,version,"
            "next_due,host_key,host_key_confirmed,mount_paths,owner_id,key_id FROM inventory.a"
            "nsible_profiles WHERE server_id=:id",
            id=server,
        )
        runs = await rows(
            s,
            "SELECT r.id,r.profile_version,r.action,r.trigger_type,r.requested_at,r.started_at,r"
            ".finished_at,r.error_code,"
            "CASE WHEN j.status IN ('pending','queued','running','retry_pending') THEN j.status"
            " WHEN j.status IN ('failed','cancelled','timed_out') THEN 'failed'"
            " ELSE r.state END AS state,r.host_key,r.execution_id,r.workflow_i"
            "d,r.submission_id "
            "FROM inventory.ansible_runs r LEFT JOIN automation.jobs j ON j.id"
            "=r.job_id WHERE r.server_id=:id "
            "ORDER BY r.requested_at DESC LIMIT 25",
            id=server,
        )
        for item in runs:
            public = item.get("host_key")
            item["fingerprint"] = (
                "SHA256:"
                + base64.b64encode(hashlib.sha256(base64.b64decode(public.split()[-1])).digest())
                .decode()
                .rstrip("=")
                if public
                else None
            )
        vault = await one(
            s, "SELECT user_id FROM security.ansible_vaults WHERE user_id=:id", id=actor.user_id
        )
        credentials_configured = profile is not None and profile["key_id"] == FORMAT
        if profile:
            editable = profile.pop("owner_id") == actor.user_id
            profile.pop("key_id")
        else:
            server_row = await one(
                s, "SELECT created_by FROM inventory.servers WHERE id=:id", id=server
            )
            editable = bool(server_row and server_row["created_by"] == actor.user_id)
        return {
            "profile": profile,
            "credentials_configured": credentials_configured,
            "vault_configured": vault is not None,
            "editable": editable,
            "runs": runs,
        }


@router.put("/{server}/ansible", response_model=Saved)
async def configure(server: UUID, body: Connection, request: Request) -> dict[str, bool]:
    auth, _ = transport(request)
    async with security_transaction(auth.database) as s:
        actor, _ = await load_principal(
            auth, s, request.cookies.get(SESSION_COOKIE), csrf_for(request)
        )
        await owned(s, actor, server)
        old = await one(
            s, "SELECT * FROM inventory.ansible_profiles WHERE server_id=:id FOR UPDATE", id=server
        )
        owner = (
            old["owner_id"]
            if old
            else (
                await one(s, "SELECT created_by FROM inventory.servers WHERE id=:id", id=server)
                or {}
            ).get("created_by")
        )
        if owner != actor.user_id:
            raise Denied(403, "personal_vault_owner_required")
        if body.version != (old["version"] if old else 0):
            raise Denied(412, "stale_version")
        vault = await one(
            s, "SELECT * FROM security.ansible_vaults WHERE user_id=:id", id=actor.user_id
        )
        if not vault:
            raise Denied(409, "personal_vault_required")
        previous = bytes(old["ciphertext"]) if old and old["key_id"] == FORMAT else None
        updates = {}
        if body.private_key is not None and body.passphrase is None:
            updates["passphrase"] = ""
        for field in SECRET_FIELDS:
            value = getattr(body, field)
            if value is not None and field != "sudo_password":
                updates[field] = value.get_secret_value()
        obsolete_fields = (
            ("private_key", "passphrase") if body.auth_method == "password" else ("password",)
        )
        for obsolete in obsolete_fields:
            updates[obsolete] = ""
        cipher = update_credentials(
            keyring(request).runtime_key(actor.user_id, vault),
            actor.user_id,
            server,
            previous,
            updates,
        )
        if not json.loads(cipher).get("private_key" if body.auth_method == "key" else "password"):
            raise Denied(422, "credentials_required")
        if old:
            outstanding = await rows(
                s,
                "SELECT j.id FROM automation.jobs j JOIN inventory.ansible_runs r ON r.job_id=j.id "
                "WHERE r.server_id=:id AND j.status IN "
                "('pending','queued','retry_pending','running')",
                id=server,
            )
            for job in outstanding:
                await s.execute(
                    text("SELECT automation.control_job(:id,'cancel')"), {"id": job["id"]}
                )
        version = old["version"] + 1 if old else 1
        kid = FORMAT
        unchanged = old is not None and old["host"] == body.host and old["port"] == body.port
        await s.execute(
            text(
                "INSERT INTO inventory.ansible_profiles(server_id,owner_id,host,po"
                "rt,username,auth_method,"
                "key_id,ciphertext,version,enabled,interval_seconds,use_sudo,mount"
                "_paths,host_key,host_key_confirmed) "
                "VALUES(:id,:owner,:host,:port,:username,:auth_method,:kid,:cipher"
                ",:version,:enabled,:interval,:sudo,CAST(:mounts AS jsonb),:key,:c"
                "onfirmed) "
                "ON CONFLICT(server_id) DO UPDATE SET host=excluded.host,port=excl"
                "uded.port,username=excluded.username,"
                "auth_method=excluded.auth_method,key_id=excluded.key_id,ciphertex"
                "t=excluded.ciphertext,version=excluded.version,"
                "enabled=excluded.enabled,interval_seconds=excluded.interval_secon"
                "ds,use_sudo=excluded.use_sudo,mount_paths=excluded.mount_paths,"
                "host_key=excluded.host_key,host_key_confirmed=excluded.host_key_c"
                "onfirmed,updated_at=clock_timestamp()"
            ),
            {
                "id": server,
                "owner": old["owner_id"] if old else actor.user_id,
                **body.model_dump(
                    exclude=set(SECRET_FIELDS) | {"mount_paths", "interval_seconds", "use_sudo"}
                ),
                "kid": kid,
                "cipher": cipher,
                "version": version,
                "interval": body.interval_seconds,
                "sudo": body.use_sudo,
                "mounts": json.dumps(body.mount_paths),
                "key": old["host_key"] if old is not None and unchanged else None,
                "confirmed": old["host_key_confirmed"] if old is not None and unchanged else False,
            },
        )
        await audit(s, actor.user_id, server, "configured", version)
    return {"saved": True}


@router.post("/{server}/ansible/confirm-key", response_model=Confirmed)
async def confirm(server: UUID, body: ConfirmKey, request: Request) -> dict[str, bool]:
    auth, _ = transport(request)
    async with security_transaction(auth.database) as s:
        actor, _ = await load_principal(
            auth, s, request.cookies.get(SESSION_COOKIE), csrf_for(request)
        )
        await owned(s, actor, server)
        run = await one(
            s,
            "SELECT r.host_key,r.profile_version FROM inventory.ansible_runs r JOIN inventory.an"
            "sible_profiles p ON p.server_id=r.server_id "
            "AND p.version=r.profile_version WHERE r.server_id=:id AND r.actio"
            "n='probe' AND r.state='succeeded' ORDER BY r.finished_at DESC LIM"
            "IT 1",
            id=server,
        )
        if not run or not run["host_key"]:
            raise Denied(409, "host_key_probe_required")
        public = run["host_key"].split()
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(base64.b64decode(public[-1])).digest()
        ).decode().rstrip("=")
        if fingerprint != body.fingerprint:
            raise Denied(409, "host_key_changed")
        await s.execute(
            text(
                "UPDATE inventory.ansible_profiles SET host_key=:key,host_key_conf"
                "irmed=true WHERE server_id=:id"
            ),
            {"id": server, "key": run["host_key"]},
        )
        await audit(
            s, actor.user_id, server, "host_key_confirmed", run["profile_version"], fingerprint
        )
    return {"confirmed": True}


@router.post("/{server}/ansible/{action}", status_code=202, response_model=RunAccepted)
async def run(
    server: UUID, action: Literal["collect", "test", "probe"], request: Request
) -> dict[str, Any]:
    auth, _ = transport(request)
    async with security_transaction(auth.database) as s:
        actor, _ = await load_principal(
            auth, s, request.cookies.get(SESSION_COOKIE), csrf_for(request)
        )
        await owned(s, actor, server)
        try:
            value = await one(
                s,
                "SELECT inventory.schedule_ansible(:id,:action,:actor) AS id",
                id=server,
                action=action,
                actor=actor.user_id,
            )
        except Exception as error:
            if getattr(getattr(error, "orig", None), "sqlstate", None) == "P0002":
                raise Denied(409, "personal_vault_credentials_required") from None
            if getattr(getattr(error, "orig", None), "sqlstate", None) == "23514":
                raise Denied(409, "host_key_confirmation_required") from None
            raise
        assert value
        return {"run_id": value["id"], "status": "pending"}
