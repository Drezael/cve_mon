"""Account-owned language choice and an administrator-only persistent instance default."""

import os
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from cve_common.jobs.contracts import Payload
from fastapi import APIRouter, Request, Response
from sqlalchemy.exc import DBAPIError

from cve_api.administration.versioning import etag, expected
from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.repository import one
from cve_api.auth.service import AuthService
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.auth.transactions import security_transaction
from cve_api.authorization.errors import Denied
from cve_api.authorization.principal import load_principal
from cve_api.status.router import operation

Locale = Literal["de", "en"]
router = APIRouter(tags=["localization"])
PUBLIC = "/api/v1/dashboard/localization"
PERSONAL = "/api/v1/dashboard/me/locale"
ADMIN = "/api/v1/dashboard/administration/localization"


class DefaultRead(Payload):
    default_locale: Locale


class PersonalUpdate(Payload):
    locale: Locale | None


class PersonalRead(PersonalUpdate, DefaultRead):
    effective_locale: Locale
    version: int


class InstanceRead(DefaultRead):
    version: int
    updated_at: datetime | None


async def bootstrap(auth: AuthService, values: Mapping[str, str] | None = None) -> None:
    values = os.environ if values is None else values
    async with security_transaction(auth.database) as s:
        await one(
            s,
            "SELECT security.bootstrap_locale(:locale)",
            locale=values.get("CVE_DEFAULT_LANGUAGE", "en"),
        )


@router.get(PUBLIC, response_model=DefaultRead)
async def public_default(request: Request) -> Any:
    auth, _ = transport(request)
    async with security_transaction(auth.database, mutation=False) as s:
        result = await one(s, "SELECT security.locale_default() AS value")
        assert result
        return result["value"]


def version(request: Request) -> int:
    match = request.headers.get("if-match")
    return 0 if match == '"0"' else expected(match)


@router.get(PERSONAL, response_model=PersonalRead)
async def personal(request: Request, response: Response) -> Any:
    return await own(request, response)


@router.put(PERSONAL, response_model=PersonalRead)
async def save_personal(body: PersonalUpdate, request: Request, response: Response) -> Any:
    return await own(request, response, body)


async def own(request: Request, response: Response, body: PersonalUpdate | None = None) -> Any:
    auth, _ = transport(request)
    wanted = version(request) if body is not None else None
    try:
        async with security_transaction(auth.database, mutation=False) as s:
            actor, _ = await load_principal(
                auth, s, request.cookies.get(SESSION_COOKIE), csrf_for(request) if body else None
            )
            result = await one(
                s,
                "SELECT security.locale_personal_set(:session_id,:version,:locale) AS value"
                if body is not None
                else "SELECT security.locale_personal(:session_id) AS value",
                session_id=actor.session_id,
                version=wanted,
                locale=body.locale if body else None,
            )
            assert result
            response.headers["ETag"] = etag(result["value"]["version"])
            return result["value"]
    except DBAPIError as error:
        if getattr(error.orig, "sqlstate", None) == "40001":
            raise Denied(412, "stale_version") from None
        raise


@router.get(ADMIN, response_model=InstanceRead)
async def instance(request: Request, response: Response) -> Any:
    async with operation(request, "instance:settings:manage") as (s, actor):
        result = await one(
            s, "SELECT security.locale_instance(:session_id) AS value", session_id=actor.session_id
        )
        assert result
        response.headers["ETag"] = etag(result["value"]["version"])
        return result["value"]


@router.put(ADMIN, response_model=InstanceRead)
async def save_instance(body: DefaultRead, request: Request, response: Response) -> Any:
    wanted = version(request)
    async with operation(request, "instance:settings:manage", mutation=True) as (s, actor):
        result = await one(
            s,
            "SELECT security.locale_instance_set(:session_id,:version,:locale) AS value",
            session_id=actor.session_id,
            version=wanted,
            locale=body.default_locale,
        )
        assert result
        response.headers["ETag"] = etag(result["value"]["version"])
        return result["value"]
