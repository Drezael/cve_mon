"""Verified transport and complete server-side identity; headers never confer user rights."""

import hmac
import ipaddress
from typing import Any
from urllib.parse import urlsplit

from fastapi import Request

from cve_api.auth.transactions import security_transaction as transaction

from .errors import AuthError
from .service import AuthService
from .sessions import LOGIN_COOKIE, SESSION_COOKIE


def service_for(request: Request) -> AuthService:
    service = getattr(request.app.state, "auth", None)
    if not isinstance(service, AuthService):
        raise AuthError(503)
    return service


def transport(request: Request) -> tuple[AuthService, str]:
    service = service_for(request)
    configured = urlsplit(service.settings.origin)
    host = request.headers.getlist("host")
    gateway = request.headers.getlist("x-cve-auth-gateway")
    scheme = request.headers.getlist("x-cve-auth-scheme")
    origins = request.headers.getlist("origin")
    if (
        len(host) != 1
        or host[0] not in {configured.netloc, configured.hostname}
        or len(gateway) != 1
        or not hmac.compare_digest(gateway[0], service.gateway)
        or scheme != ["https"]
    ):
        raise AuthError(403)
    if (request.method not in {"GET", "HEAD"} and origins != [service.settings.origin]) or (
        origins and origins != [service.settings.origin]
    ):
        raise AuthError(403)
    # Nginx overwrites these headers. They are consulted only after verifying its private gate.
    addresses = request.headers.getlist("x-real-ip")
    try:
        if len(addresses) != 1:
            raise ValueError
        ip = str(ipaddress.ip_address(addresses[0]))
    except ValueError:
        raise AuthError(403) from None
    # Cookie shadowing must not select a different authentication context.
    if len(request.headers.getlist("cookie")) > 1:
        raise AuthError(403)
    pairs = [part.strip().split("=", 1)[0] for part in request.headers.get("cookie", "").split(";")]
    if any(pairs.count(name) > 1 for name in (SESSION_COOKIE, LOGIN_COOKIE)):
        raise AuthError(403)
    return service, ip


def csrf_for(request: Request) -> str:
    values = request.headers.getlist("x-csrf-token")
    if len(values) != 1 or not 20 <= len(values[0]) <= 100:
        raise AuthError(403)
    return values[0]


async def authenticated_user(request: Request) -> dict[str, Any]:
    service, _ = transport(request)
    async with transaction(service.database) as session:
        current = await service.resolve(session, request.cookies.get(SESSION_COOKIE), full=True)
        return {
            "id": current["user"]["id"],
            "display_name": current["user"]["display_name"],
            "mfa_verified": current["mfa_verified_at"] is not None,
        }
