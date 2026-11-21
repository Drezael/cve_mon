"Preflight and commit-time authorization, bounded parsing, admission and immutable acceptance."

import asyncio
import hashlib
import hmac
import logging
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import Any
from uuid import UUID

from cve_common.config.secrets import read_secret
from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.errors import AuthError
from cve_api.auth.repository import execute, one
from cve_api.auth.service import AuthService
from cve_api.auth.transactions import security_transaction
from cve_api.authorization.engine import decide, function_decision
from cve_api.authorization.principal import load_principal
from cve_api.servers.schemas import Metadata
from cve_api.technical_auth.certificates import crl
from cve_api.technical_auth.proxy_identity import TechnicalProof

from .discovery import apply_metadata, resolve
from .errors import UploadError
from .events import audit
from .parser import Validated, parse, schema
from .repository import FIELDS, Source, response, store
from .settings import InventorySettings


class InventoryService:
    def __init__(self, settings: InventorySettings, auth: AuthService) -> None:
        self.settings, self.auth = settings, auth
        self.database = Database(settings.database)
        self.gateway = read_secret(settings.gateway_file).get_secret_value()
        self.key = read_secret(settings.token_key_file).get_secret_value().encode()
        if len(self.gateway) < 43 or len(self.key) < 43:
            raise ValueError("Private inventory capabilities required")
        self.slots = asyncio.BoundedSemaphore(settings.concurrent_uploads)

    async def open(self) -> None:
        schema()
        crl(self.settings.client_crl_file, self.settings.client_ca_file)
        self.database.open()

    async def close(self) -> None:
        await self.database.close()

    async def ready(self) -> bool:
        try:
            crl(self.settings.client_crl_file, self.settings.client_ca_file)
        except UploadError:
            return False
        return await self.database.ready(1)

    def verifier(self, tid: UUID, secret: str) -> bytes:
        return hmac.digest(self.key, (str(tid) + "." + secret).encode(), hashlib.sha256)

    async def rate(self, kind: str, value: str, limit: int) -> None:
        key = hmac.digest(self.key, (kind + ":" + value).encode(), hashlib.sha256)
        async with transaction(self.database) as s:
            row = await one(
                s, "SELECT security.inventory_rate(:key,:limit) AS allowed", key=key, limit=limit
            )
        if not row or not row["allowed"]:
            raise UploadError(429, "rate_limited")

    async def metric(self, code: str) -> None:
        try:
            async with transaction(self.database) as s:
                await execute(s, "SELECT security.inventory_metric(:code)", code=code)
        except SQLAlchemyError:
            pass

    @asynccontextmanager
    async def admission(self, ip: str, channel: str) -> AsyncIterator[None]:
        started = time.monotonic()
        status = 200 if channel == "status" else 202
        acquired = False
        try:
            try:
                async with asyncio.timeout(2):
                    await self.rate("global", "all", self.settings.global_rate)
                    await self.rate("ip", ip, self.settings.ip_rate)
            except TimeoutError:
                raise UploadError(503, "database_unavailable") from None
            if channel != "status":
                try:
                    async with asyncio.timeout(2):
                        await self.slots.acquire()
                except TimeoutError:
                    raise UploadError(429, "upload_capacity") from None
                acquired = True
            yield
        except (UploadError, AuthError) as error:
            status = error.status
            if status >= 500:
                raise
            category = {
                401: "authentication_error",
                403: "permission_error",
                404: "permission_error",
                413: "size_error",
                422: "schema_error",
                400: "parser_error",
                429: "quota_error",
            }.get(status, "permission_error")
            await self.metric(category)
            # Rate-bound aggregate denials, without request bodies or unverified identities.
            try:
                await self.rate("denied", ip, 10)
                async with transaction(self.database) as s:
                    await audit(
                        s, "rejected", success=False, details={"channel": channel, "status": status}
                    )
            except (SQLAlchemyError, UploadError):
                pass
            raise
        except IntegrityError as error:
            constraint = getattr(getattr(error.orig, "diag", None), "constraint_name", None)
            status = 429 if constraint == "submission_quota" else 409
            await self.metric("quota_error" if status == 429 else "permission_error")
            raise UploadError(status, "acceptance_conflict") from None
        except SQLAlchemyError:
            status = 503
            raise
        finally:
            if acquired:
                self.slots.release()
            logging.getLogger("cve.inventory." + channel).info(
                "request",
                extra={
                    "status": status,
                    "duration_ms": round((time.monotonic() - started) * 1000, 3),
                },
            )

    def key_for(self, header: str | None, value: Validated) -> str:
        key = header if header is not None else str(value.inventory_id)
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", key):
            raise UploadError(400, "idempotency_key")
        return key

    async def technical(
        self, s: AsyncSession, proof: TechnicalProof, *, touch: bool = False
    ) -> Source:
        row = await one(
            s,
            "SELECT * FROM security.inventory_identity(:id,:verifier,:fingerprint,:touch)",
            id=proof.token_id,
            verifier=self.verifier(proof.token_id, proof.secret),
            fingerprint=proof.fingerprint,
            touch=touch,
        )
        if row is None:
            raise UploadError(401, "invalid_credentials")
        active = await one(
            s, "SELECT status FROM inventory.servers WHERE id=:id", id=row["server_id"]
        )
        if row["server_id"] is not None and not active:
            raise UploadError(404, "server_not_found")
        if active and active["status"] != "active":
            raise UploadError(409, "server_inactive")
        return Source(
            "ansible_api",
            row["principal_id"],
            row["server_id"],
            token_id=row["token_id"],
            certificate_id=row["certificate_id"],
            fingerprint=proof.fingerprint,
        )

    async def technical_preflight(self, proof: TechnicalProof) -> None:
        async with security_transaction(self.database, mutation=False) as s:
            source = await self.technical(s, proof)
        await self.rate("client", str(source.identity), self.settings.client_rate)
        await self.rate("token", str(proof.token_id), self.settings.token_rate)
        if source.server_id is not None:
            await self.rate("server", str(source.server_id), self.settings.server_rate)

    async def dashboard(
        self,
        s: AsyncSession,
        cookie: str | None,
        csrf: str | None,
        sid: UUID | None,
        *,
        reading: bool = False,
    ) -> Source:
        a, current = await load_principal(self.auth, s, cookie, csrf)
        managing = "server:inventory:manage" in a.permissions
        action = (
            "inventory:read"
            if reading
            else ("server:inventory:manage" if managing else "inventory:upload:dashboard")
        )
        if not function_decision(a, action).allow:
            raise UploadError(403, "missing_permission")
        if sid is None:
            return Source(
                "dashboard_file",
                a.user_id,
                UUID(int=0),
                user_id=a.user_id,
                session_id=current["id"],
            )
        if not reading and managing:
            target = await one(
                s, "SELECT status,created_by FROM inventory.servers WHERE id=:id", id=sid
            )
            grant = await one(
                s,
                "SELECT can_upload FROM security.user_server_access "
                "WHERE user_id=:user AND server_id=:id",
                user=a.user_id,
                id=sid,
            )
            allowed = bool(
                target
                and target["status"] == "active"
                and (
                    a.administrator
                    or target["created_by"] == a.user_id
                    or (grant and grant["can_upload"])
                )
            )
        else:
            allowed = (await decide(s, a, action, sid)).allow
        if not allowed:
            raise UploadError(404, "invisible_server")
        return Source("dashboard_file", a.user_id, sid, user_id=a.user_id, session_id=current["id"])

    async def dashboard_preflight(self, cookie: str | None, csrf: str) -> None:
        async with security_transaction(self.auth.database, mutation=False) as s:
            source = await self.dashboard(s, cookie, csrf, None)
        await self.rate("user", str(source.identity), self.settings.user_rate)

    async def submit_technical(
        self, proof: TechnicalProof, raw: bytes, key: str | None
    ) -> dict[str, Any]:
        value = await parse(raw, self.settings)
        async with security_transaction(self.database, mutation=False) as s:
            source = await self.technical(s, proof, touch=True)
            if source.server_id is None:
                if value.host is None:
                    raise UploadError(422, "discovery_contract_required")
                owner = await one(
                    s, "SELECT security.collector_actor(:id) AS id", id=source.identity
                )
                if not owner or not owner["id"]:
                    raise UploadError(403, "collector_owner_unavailable")
                sid = await resolve(s, value, owner["id"], principal=source.identity)
                source = replace(source, server_id=sid)
                rate_key = hmac.digest(self.key, ("server:" + str(sid)).encode(), hashlib.sha256)
                budget = await one(
                    s,
                    "SELECT security.inventory_rate(:key,:limit) AS allowed",
                    key=rate_key,
                    limit=self.settings.server_rate,
                )
                if not budget or not budget["allowed"]:
                    raise UploadError(429, "rate_limited")
            elif value.host is not None:
                binding = await one(
                    s,
                    "SELECT monitoring_id FROM inventory.host_identities WHERE server_id=:id",
                    id=source.server_id,
                )
                if not binding or str(binding["monitoring_id"]) != value.host["monitoring_id"]:
                    raise UploadError(404, "server_not_authorized")
            elif source.server_id != value.server_id:
                raise UploadError(404, "server_not_authorized")
            result = await store(s, source, value, raw, self.key_for(key, value))
        await self.metric("duplicate" if result["duplicate"] else "technical_accepted")
        return result

    async def submit_dashboard(
        self,
        cookie: str | None,
        csrf: str,
        sid: UUID | None,
        raw: bytes,
        key: str | None,
        metadata: Metadata | None = None,
    ) -> dict[str, Any]:
        value = await parse(raw, self.settings)
        async with security_transaction(self.auth.database, mutation=False) as s:
            actor = await self.dashboard(s, cookie, csrf, None)
            sid = await resolve(s, value, actor.identity, sid)
            source = await self.dashboard(s, cookie, csrf, sid)
            await self.rate("server", str(sid), self.settings.server_rate)
            result = await store(s, source, value, raw, self.key_for(key, value))
            if metadata is not None:
                await apply_metadata(s, result, actor.identity, metadata)
        await self.metric("duplicate" if result["duplicate"] else "dashboard_accepted")
        return result

    async def status_technical(self, proof: TechnicalProof, sid: UUID) -> dict[str, Any]:
        async with security_transaction(self.database, mutation=False) as s:
            source = await self.technical(s, proof)
            row = await one(
                s,
                "SELECT "
                + FIELDS
                + " FROM inventory.submissions WHERE id=:id AND source=:source AND s"
                "ource_identity=:identity AND (CAST(:server AS uuid) IS NULL OR server_id=:server)",
                id=sid,
                source=source.kind,
                identity=source.identity,
                server=source.server_id,
            )
            if row is None:
                raise UploadError(404, "submission_not_found")
            return response(row)

    async def status_dashboard(self, cookie: str | None, sid: UUID) -> dict[str, Any]:
        async with security_transaction(self.auth.database, mutation=False) as s:
            source = await self.dashboard(s, cookie, None, None, reading=True)
            row = await one(
                s,
                "SELECT "
                + FIELDS
                + " FROM inventory.submissions WHERE id=:id AND source='dashboard_fi"
                "le' AND source_identity=:identity",
                id=sid,
                identity=source.identity,
            )
            if row is None:
                raise UploadError(404, "submission_not_found")
            await self.dashboard(s, cookie, None, row["server_id"], reading=True)
            return response(row)
