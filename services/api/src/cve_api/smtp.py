"""Administrator SMTP settings; secret envelopes never enter queue payloads or responses."""

import json
from collections.abc import Callable, Coroutine
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID

from cve_common.http.errors import validation_response
from cve_common.smtp_settings import PersonalSMTPUpdate, SMTPConfig, SMTPKeyring, SMTPUpdate
from fastapi import APIRouter, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text
from starlette.responses import Response

from cve_api.auth.dependencies import transport
from cve_api.auth.repository import one
from cve_api.authorization.errors import Denied
from cve_api.status.router import operation


class SecretValidationRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def safe(request: Request) -> Response:
            try:
                return await handler(request)
            except RequestValidationError as error:
                # Validation input may contain raw credentials; never echo it to the client.
                return validation_response(request, error)

        return safe


router = APIRouter(tags=["smtp-configuration"], route_class=SecretValidationRoute)
ADMIN = "/api/v1/dashboard/administration/smtp"
PERSONAL = "/api/v1/dashboard/notifications/mail"


class SMTPRead(SMTPConfig):
    id: UUID | None
    version: int
    state: Literal[
        "unconfigured", "waiting", "authorized", "applying", "applied", "failed", "cancelled"
    ]
    username: str
    password_configured: bool
    created_at: datetime | None
    finished_at: datetime | None
    error_code: str | None
    execution_id: str | None


def keyring(request: Request) -> SMTPKeyring:
    auth, _ = transport(request)
    return SMTPKeyring(Path(auth.settings.keyring_file).with_name("smtp-keys.json"))


def public(row: dict[str, Any], secrets: dict[str, Any]) -> dict[str, Any]:
    return {
        **row["configuration"],
        "id": row["id"],
        "version": row["version"],
        "state": row["state"],
        "username": secrets.get("username", ""),
        "password_configured": bool(secrets.get("password")),
        "created_at": row["created_at"],
        "finished_at": row["finished_at"],
        "error_code": row["error_code"],
        "execution_id": row["execution_id"],
    }


@router.get(ADMIN, response_model=SMTPRead)
async def settings(request: Request) -> Any:
    async with operation(request, "notification:smtp:manage") as (s, _actor):
        row = await one(
            s,
            "SELECT * FROM automation.smtp_configs WHERE owner_id IS NULL ORDER BY "
            "version DESC LIMIT 1",
        )
        if row:
            secret = keyring(request).decrypt(row["id"], row["key_id"], bytes(row["credentials"]))
            return public(row, secret)
        emails = (
            (
                await s.execute(
                    text(
                        "SELECT email FROM security.users WHERE status='active' "
                        "ORDER BY email LIMIT 1000"
                    )
                )
            )
            .scalars()
            .all()
        )
        return {
            **SMTPConfig(recipients=list(emails)).model_dump(),
            "id": None,
            "version": 0,
            "state": "unconfigured",
            "username": "",
            "password_configured": False,
            "created_at": None,
            "finished_at": None,
            "error_code": None,
            "execution_id": None,
        }


@router.put(ADMIN, status_code=202, response_model=SMTPRead)
async def configure(
    body: SMTPUpdate, request: Request, idempotency_key: Annotated[UUID, Header()]
) -> Any:
    return await save(body, request, idempotency_key, personal=False)


class PersonalSMTPRead(SMTPRead):
    mode: Literal["system", "custom"]
    system_available: bool


@router.get(PERSONAL, response_model=PersonalSMTPRead)
async def personal_settings(request: Request) -> Any:
    async with operation(request, "notification:read") as (s, actor):
        row = await one(
            s,
            "SELECT * FROM automation.smtp_configs WHERE owner_id=:owner ORDER BY "
            "version DESC LIMIT 1",
            owner=actor.user_id,
        )
        system = await one(
            s,
            "SELECT configuration FROM automation.smtp_configs WHERE owner_id IS "
            "NULL AND state='applied' ORDER BY version DESC LIMIT 1",
        )
        available = bool(system and system["configuration"]["enabled"])
        if row:
            secret = keyring(request).decrypt(row["id"], row["key_id"], bytes(row["credentials"]))
            return {**public(row, secret), "system_available": available}
        user = await one(s, "SELECT email FROM security.users WHERE id=:id", id=actor.user_id)
        return {
            **SMTPConfig().model_dump(),
            "mode": "system",
            "recipients": [user["email"]] if user and user["email"] else [],
            "id": None,
            "version": 0,
            "state": "unconfigured",
            "username": "",
            "password_configured": False,
            "created_at": None,
            "finished_at": None,
            "error_code": None,
            "execution_id": None,
            "system_available": available,
        }


@router.put(PERSONAL, status_code=202, response_model=PersonalSMTPRead)
async def configure_personal(
    body: PersonalSMTPUpdate, request: Request, idempotency_key: Annotated[UUID, Header()]
) -> Any:
    return await save(body, request, idempotency_key, personal=True)


async def save(body: SMTPUpdate, request: Request, idempotency_key: UUID, *, personal: bool) -> Any:
    permission = "notification:preferences:update" if personal else "notification:smtp:manage"
    async with operation(request, permission, True) as (s, actor):
        owner = actor.user_id if personal else None
        await s.execute(text("SELECT pg_advisory_xact_lock(7353001)"))
        existing = await one(
            s, "SELECT * FROM automation.smtp_configs WHERE id=:id", id=idempotency_key
        )
        if existing and (
            existing["owner_id"] != owner or existing["requested_by"] != actor.user_id
        ):
            raise Denied(409, "idempotency_key_conflict")
        latest = await one(
            s,
            "SELECT * FROM automation.smtp_configs WHERE owner_id IS NOT DISTINCT "
            "FROM CAST(:owner AS uuid) ORDER BY version DESC LIMIT 1",
            owner=owner,
        )
        ring = keyring(request)
        base = existing or latest
        old = ring.decrypt(base["id"], base["key_id"], bytes(base["credentials"])) if base else {}
        password = (
            body.password.get_secret_value()
            if body.password and body.password.get_secret_value()
            else old.get("password", "")
        )
        secrets = {"username": body.username, "password": password}
        config = body.model_dump(exclude={"version", "username", "password"})
        if (
            body.enabled
            and not body.is_mailhog
            and (not secrets["username"] or not secrets["password"])
        ):
            raise Denied(422, "smtp_credentials_required")
        if existing:
            if existing["configuration"] != config or old != secrets:
                raise Denied(409, "idempotency_key_conflict")
            row = existing
        else:
            if body.version != (latest["version"] if latest else 0):
                raise Denied(412, "smtp_configuration_changed")
            key, cipher = ring.encrypt(idempotency_key, secrets)
            await s.execute(
                text(
                    "SELECT "
                    "automation.request_smtp_scoped(:id,:actor,:owner,:version,CAST(:config"
                    " AS jsonb),:key,:cipher)"
                ),
                {
                    "id": idempotency_key,
                    "actor": actor.user_id,
                    "owner": owner,
                    "version": body.version,
                    "config": json.dumps(config),
                    "key": key,
                    "cipher": cipher,
                },
            )
            inserted = await one(
                s, "SELECT * FROM automation.smtp_configs WHERE id=:id", id=idempotency_key
            )
            assert inserted
            row = inserted
        result = public(row, secrets)
        if personal:
            system = await one(
                s,
                "SELECT configuration FROM automation.smtp_configs WHERE owner_id IS"
                " NULL AND state='applied' ORDER BY version DESC LIMIT 1",
            )
            result["system_available"] = bool(system and system["configuration"]["enabled"])
        return result


class SMTPTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recipient: str | None = Field(default=None, max_length=254)

    @field_validator("recipient")
    @classmethod
    def address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        result = SMTPConfig.address(value)
        if not result:
            raise ValueError("Test recipient required")
        return result


class SMTPTestRead(BaseModel):
    id: UUID | None = None
    state: Literal[
        "unconfigured", "waiting", "authorized", "running", "sent", "failed", "cancelled"
    ] = "unconfigured"
    created_at: datetime | None = None
    finished_at: datetime | None = None
    error_code: str | None = None
    execution_id: str | None = None


def test_public(row: dict[str, Any] | None) -> SMTPTestRead:
    return (
        SMTPTestRead.model_validate({k: row[k] for k in SMTPTestRead.model_fields})
        if row
        else SMTPTestRead()
    )


async def read_test(request: Request, *, personal: bool) -> SMTPTestRead:
    async with operation(
        request, "notification:read" if personal else "notification:smtp:manage"
    ) as (s, actor):
        return test_public(
            await one(
                s,
                "SELECT * FROM automation.smtp_tests WHERE requested_by=:actor AND "
                "owner_id IS NOT DISTINCT FROM CAST(:owner AS uuid) "
                "ORDER BY created_at DESC,id DESC LIMIT 1",
                actor=actor.user_id,
                owner=actor.user_id if personal else None,
            )
        )


async def queue_test(
    body: SMTPTestRequest, request: Request, identity: UUID, *, personal: bool
) -> SMTPTestRead:
    permission = "notification:preferences:update" if personal else "notification:smtp:manage"
    async with operation(request, permission, True) as (s, actor):
        owner = actor.user_id if personal else None
        await s.execute(text("SELECT pg_advisory_xact_lock(7353002)"))
        old = await one(s, "SELECT * FROM automation.smtp_tests WHERE id=:id", id=identity)
        if old:
            if (
                old["requested_by"] != actor.user_id
                or old["owner_id"] != owner
                or (body.recipient and old["recipients"] != [body.recipient])
            ):
                raise Denied(409, "idempotency_key_conflict")
            return test_public(old)
        count = await one(
            s,
            "SELECT count(*) AS n FROM automation.smtp_tests WHERE "
            "requested_by=:actor AND created_at>clock_timestamp()-interval '5 minutes'",
            actor=actor.user_id,
        )
        if count and count["n"] >= 5:
            raise Denied(429, "smtp_test_rate_limit")
        selected = await one(
            s,
            "SELECT * FROM automation.smtp_configs WHERE owner_id IS NOT "
            "DISTINCT FROM CAST(:owner AS uuid) ORDER BY version DESC LIMIT 1",
            owner=owner,
        )
        if selected and selected["state"] != "applied":
            raise Denied(409, "smtp_configuration_not_applied")
        recipients = selected["configuration"]["recipients"] if personal and selected else []
        if not selected or (personal and selected["configuration"].get("mode") == "system"):
            selected = await one(
                s,
                "SELECT * FROM automation.smtp_configs WHERE owner_id IS NULL ORDER "
                "BY version DESC LIMIT 1",
            )
        if (
            not selected
            or selected["state"] != "applied"
            or not selected["configuration"]["enabled"]
        ):
            raise Denied(409, "smtp_not_configured")
        if body.recipient:
            recipients = [body.recipient]
        if not recipients:
            user = await one(s, "SELECT email FROM security.users WHERE id=:id", id=actor.user_id)
            recipients = [user["email"]] if user and user["email"] else []
        if not recipients:
            raise Denied(422, "smtp_test_recipient_required")
        await s.execute(
            text(
                "SELECT "
                "automation.request_smtp_test(:id,:actor,:owner,:config,CAST(:recipients AS jsonb))"
            ),
            {
                "id": identity,
                "actor": actor.user_id,
                "owner": owner,
                "config": selected["id"],
                "recipients": json.dumps(recipients),
            },
        )
        return test_public(
            await one(s, "SELECT * FROM automation.smtp_tests WHERE id=:id", id=identity)
        )


@router.get(ADMIN + "/test", response_model=SMTPTestRead)
async def admin_test_status(request: Request) -> SMTPTestRead:
    return await read_test(request, personal=False)


@router.get(PERSONAL + "/test", response_model=SMTPTestRead)
async def personal_test_status(request: Request) -> SMTPTestRead:
    return await read_test(request, personal=True)


@router.post(ADMIN + "/test", status_code=202, response_model=SMTPTestRead)
async def admin_test(
    body: SMTPTestRequest, request: Request, idempotency_key: Annotated[UUID, Header()]
) -> SMTPTestRead:
    return await queue_test(body, request, idempotency_key, personal=False)


@router.post(PERSONAL + "/test", status_code=202, response_model=SMTPTestRead)
async def personal_test(
    body: SMTPTestRequest, request: Request, idempotency_key: Annotated[UUID, Header()]
) -> SMTPTestRead:
    return await queue_test(body, request, idempotency_key, personal=True)
