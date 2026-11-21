"Strong existing admin policy, explicit server binding and one-time credential disclosure."

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

from cve_common.logging.redaction import register_secret
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.repository import execute, one
from cve_api.authorization.administration import Administration
from cve_api.inventories.errors import UploadError
from cve_api.inventories.events import audit
from cve_api.inventories.service import InventoryService
from cve_api.servers.schemas import Lifecycle

from .certificates import fingerprint, registered
from .schemas import CertificateCreate, ClientCreate, TokenCreate, TokenRotate

CLIENT = "id,name,status,created_at,version"
CERT = "id,principal_id,not_before,expires_at,revoked_at,created_at"
TOKEN = (
    "id,principal_id,server_id,certificate_id,scope,created_at,expires"
    "_at,revoked_at,disabled,last_used_at,CASE WHEN revoked_at IS NOT NULL "
    "THEN 'revoked' WHEN disabled THEN 'disabled' WHEN expires_at<=clock_timestamp() "
    "THEN 'expired' ELSE 'active' END AS status"
)


class Credentials:
    def __init__(self, inventory: InventoryService) -> None:
        self.inventory = inventory
        self.admin = Administration(inventory.auth)

    async def listing(
        self, cookie: str | None, cid: UUID | None = None, kind: str = "clients"
    ) -> dict[str, Any]:
        async with self.admin.operation(cookie, None, "server:acl:manage") as (s, _, _):
            if kind == "clients":
                query = (
                    "SELECT " + CLIENT + " FROM security.technical_principals ORDER BY id LIMIT 100"
                )
            elif kind == "certificates":
                query = (
                    "SELECT "
                    + CERT
                    + ",encode(fingerprint,'hex') AS fingerprint FROM security.technical"
                    "_certificates WHERE principal_id=:id ORDER BY id LIMIT 100"
                )
            elif kind == "tokens":
                query = (
                    "SELECT "
                    + TOKEN
                    + " FROM security.api_tokens WHERE principal_id=:id AND runtime_vers"
                    "ion=1 ORDER BY id LIMIT 100"
                )
            else:
                raise UploadError(404)
            result = (await s.execute(text(query), {"id": cid})).mappings().all()
            return {"items": [dict(r) for r in result], "limit": 100}

    async def client(self, s: AsyncSession, cid: UUID, *, active: bool = True) -> dict[str, Any]:
        row = await one(
            s,
            "SELECT " + CLIENT + " FROM security.technical_principals WHERE id=:id FOR UPDATE",
            id=cid,
        )
        if not row:
            raise UploadError(404, "client_not_found")
        if active and row["status"] != "active":
            raise UploadError(409, "client_disabled")
        return row

    async def create(self, cookie: str | None, csrf: str, body: ClientCreate) -> dict[str, Any]:
        async with self.admin.operation(cookie, csrf, "server:acl:manage", mutation=True) as (
            s,
            a,
            _,
        ):
            row = await one(
                s,
                "INSERT INTO security.technical_principals(name,status) VALUES(:na"
                "me,'active') RETURNING " + CLIENT,
                name=body.name,
            )
            assert row is not None
            await audit(s, "client_created", actor=a.user_id, target=row["id"])
            return row

    async def client_status(
        self, cookie: str | None, csrf: str, cid: UUID, enabled: bool, body: Lifecycle
    ) -> dict[str, Any]:
        async with self.admin.operation(cookie, csrf, "server:acl:manage", mutation=True) as (
            s,
            a,
            _,
        ):
            await self.client(s, cid, active=False)
            row = await one(
                s,
                "UPDATE security.technical_principals SET status=:status,version=v"
                "ersion+1 WHERE id=:id RETURNING " + CLIENT,
                status="active" if enabled else "disabled",
                id=cid,
            )
            assert row is not None
            await audit(
                s, "client_enabled" if enabled else "client_disabled", actor=a.user_id, target=cid
            )
            return row

    async def certificate(
        self, cookie: str | None, csrf: str, cid: UUID, body: CertificateCreate
    ) -> dict[str, Any]:
        cert = registered(
            body.certificate_pem,
            body.chain_pem,
            self.inventory.settings.client_ca_file,
            self.inventory.settings.client_crl_file,
        )
        async with self.admin.operation(cookie, csrf, "server:acl:manage", mutation=True) as (
            s,
            a,
            _,
        ):
            await self.client(s, cid)
            row = await one(
                s,
                "INSERT INTO security.technical_certificates(principal_id,fingerpr"
                "int,certificate_pem,not_before,expires_at,issued_by) "
                "VALUES(:id,:fingerprint,:pem,:before,:expiry,:actor) RETURNING " + CERT,
                id=cid,
                fingerprint=fingerprint(cert),
                pem=body.certificate_pem.strip(),
                before=cert.not_valid_before_utc,
                expiry=cert.not_valid_after_utc,
                actor=a.user_id,
            )
            assert row is not None
            row["fingerprint"] = fingerprint(cert).hex()
            await audit(
                s,
                "certificate_registered",
                actor=a.user_id,
                target=row["id"],
                details={"client_id": cid},
            )
            return row

    async def issue_in(
        self, s: AsyncSession, cid: UUID, actor: UUID, body: TokenCreate
    ) -> dict[str, Any]:
        await self.client(s, cid)
        cert = await one(
            s,
            "SELECT * FROM security.technical_certificates WHERE id=:cert AND "
            "principal_id=:id AND revoked_at IS NULL",
            cert=body.certificate_id,
            id=cid,
        )
        if not cert:
            raise UploadError(404, "certificate_not_found")
        # PKI status is rechecked at issuance, and again on each technical request.
        registered(
            cert["certificate_pem"],
            "",
            self.inventory.settings.client_ca_file,
            self.inventory.settings.client_crl_file,
        )
        now = datetime.now(UTC)
        expiry = body.expires_at
        if expiry.tzinfo is None or not now + timedelta(minutes=5) <= expiry <= min(
            now + timedelta(days=90), cert["expires_at"]
        ):
            raise UploadError(422, "token_lifetime")
        if body.owner_user_id is not None:
            owner = await one(
                s,
                "SELECT id FROM security.users WHERE id=:id AND status='active' "
                "AND EXISTS(SELECT 1 FROM security.user_roles ur JOIN "
                "security.role_permissions rp ON rp.role_id=ur.role_id "
                "WHERE ur.user_id=:id AND rp.permission_code='server:inventory:manage')",
                id=body.owner_user_id,
            )
            if not owner:
                raise UploadError(422, "collector_owner_permission")
            old = await one(
                s, "SELECT user_id FROM security.collector_owners WHERE principal_id=:id", id=cid
            )
            if old and old["user_id"] != body.owner_user_id:
                raise UploadError(409, "collector_owner_conflict")
            await execute(
                s,
                "INSERT INTO security.collector_owners(principal_id,user_id) "
                "VALUES(:id,:owner) ON CONFLICT DO NOTHING",
                id=cid,
                owner=body.owner_user_id,
            )
        else:
            server = await one(
                s,
                "SELECT id FROM inventory.servers WHERE id=:id AND status='active'",
                id=body.server_id,
            )
            if not server:
                raise UploadError(404, "server_not_found")
            await execute(
                s,
                "INSERT INTO security.principal_server_access(principal_id,server_id) "
                "VALUES(:client,:server) ON CONFLICT DO NOTHING",
                client=cid,
                server=body.server_id,
            )
        tid = uuid4()
        secret = secrets.token_urlsafe(32)
        raw = str(tid) + "." + secret
        register_secret(SecretStr(raw))
        row = await one(
            s,
            "INSERT INTO security.api_tokens(id,principal_id,verifier,expires_"
            "at,key_id,scope,server_id,certificate_id,issued_by,runtime_versio"
            "n) "
            "VALUES(:id,:principal,:verifier,:expiry,'inventory-v1',:scope,"
            ":server,:certificate,:actor,1) RETURNING " + TOKEN,
            id=tid,
            principal=cid,
            verifier=self.inventory.verifier(tid, secret),
            expiry=expiry,
            server=body.server_id,
            scope="inventory:discover" if body.owner_user_id else "inventory:submit",
            certificate=body.certificate_id,
            actor=actor,
        )
        assert row is not None
        return {**row, "token": raw, "one_time": True}

    async def issue(
        self, cookie: str | None, csrf: str, cid: UUID, body: TokenCreate
    ) -> dict[str, Any]:
        async with self.admin.operation(cookie, csrf, "server:acl:manage", mutation=True) as (
            s,
            a,
            _,
        ):
            row = await self.issue_in(s, cid, a.user_id, body)
            await audit(
                s,
                "token_issued",
                actor=a.user_id,
                target=row["id"],
                details={
                    "client_id": cid,
                    "server_id": body.server_id,
                    "certificate_id": body.certificate_id,
                },
            )
            return row

    async def revoke(
        self,
        cookie: str | None,
        csrf: str,
        kind: Literal["token", "certificate"],
        identifier: UUID,
        body: Lifecycle,
        *,
        disable: bool = False,
    ) -> dict[str, Any]:
        async with self.admin.operation(cookie, csrf, "server:acl:manage", mutation=True) as (
            s,
            a,
            _,
        ):
            table = "security.api_tokens" if kind == "token" else "security.technical_certificates"
            fields = TOKEN if kind == "token" else CERT
            changes = (
                "disabled=true" if disable else "revoked_at=coalesce(revoked_at,clock_timestamp())"
            )
            extra = " AND runtime_version=1" if kind == "token" else ""
            row = await one(
                s,
                "UPDATE "
                + table
                + " SET "
                + changes
                + " WHERE id=:id"
                + extra
                + " RETURNING "
                + fields,
                id=identifier,
            )
            if not row:
                raise UploadError(404, "credential_not_found")
            if kind == "certificate":
                await execute(
                    s,
                    "UPDATE security.api_tokens SET revoked_at=coalesce(revoked_at,clo"
                    "ck_timestamp()) WHERE certificate_id=:id",
                    id=identifier,
                )
            await audit(
                s,
                "token_disabled" if disable else kind + "_revoked",
                actor=a.user_id,
                target=identifier,
            )
            return row

    async def rotate(
        self, cookie: str | None, csrf: str, tid: UUID, body: TokenRotate
    ) -> dict[str, Any]:
        async with self.admin.operation(cookie, csrf, "server:acl:manage", mutation=True) as (
            s,
            a,
            _,
        ):
            old = await one(
                s,
                "SELECT "
                + TOKEN
                + " FROM security.api_tokens WHERE id=:id AND runtime_version=1 FOR UPDATE",
                id=tid,
            )
            if not old or old["revoked_at"] is not None:
                raise UploadError(404, "token_not_found")
            collector_owner = None
            if old["server_id"] is None:
                owner = await one(
                    s,
                    "SELECT user_id FROM security.collector_owners WHERE principal_id=:id",
                    id=old["principal_id"],
                )
                if not owner:
                    raise UploadError(409, "collector_owner_unavailable")
                collector_owner = owner["user_id"]
            row = await self.issue_in(
                s,
                old["principal_id"],
                a.user_id,
                TokenCreate(
                    server_id=old["server_id"],
                    owner_user_id=collector_owner,
                    certificate_id=body.certificate_id or old["certificate_id"],
                    expires_at=body.expires_at,
                ),
            )
            await execute(
                s,
                "UPDATE security.api_tokens SET revoked_at=clock_timestamp() WHERE id=:id",
                id=tid,
            )
            await audit(
                s,
                "token_rotated",
                actor=a.user_id,
                target=tid,
                details={"replacement_id": row["id"], "server_id": old["server_id"]},
            )
            return row
