"""Pure ASGI context isolation and strict hosts; Phase 6 trusts no identity/proxy headers."""

import logging
import time

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cve_common.http.metrics import WINDOW
from cve_common.http.responses import problem
from cve_common.logging.correlation import correlation_id, request_id, valid_id


class TechnicalMiddleware:
    def __init__(self, app: ASGIApp, allowed_hosts: list[str]) -> None:
        self.app = app
        self.allowed_hosts = set(allowed_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        rid = valid_id(
            headers.get("x-request-id") if len(headers.getlist("x-request-id")) == 1 else None
        )
        cid = (
            valid_id(headers.get("x-correlation-id"))
            if len(headers.getlist("x-correlation-id")) == 1
            else rid
        )
        rtoken = request_id.set(rid)
        ctoken = correlation_id.set(cid)
        started = time.monotonic()
        status = 500
        sent = False

        async def wrapped(message: Message) -> None:
            nonlocal status, sent
            if message["type"] == "http.response.start":
                sent = True
                status = message["status"]
                response_headers = MutableHeaders(scope=message)
                response_headers["X-Request-ID"] = rid
                response_headers["X-Correlation-ID"] = cid
                response_headers["Cache-Control"] = "no-store"
                response_headers["X-Content-Type-Options"] = "nosniff"
            await send(message)

        try:
            hosts = headers.getlist("host")
            authority = hosts[0] if len(hosts) == 1 else ""
            host, separator, port = authority.partition(":")
            valid_port = not separator or (
                len(port) <= 5 and port.isascii() and port.isdigit() and 1 <= int(port) <= 65535
            )
            if host.lower() not in self.allowed_hosts or not valid_port:
                await problem(400)(scope, receive, wrapped)
                return
            cleaned = dict(scope)
            cleaned["headers"] = [
                (k, v)
                for k, v in scope["headers"]
                if k.lower() != b"forwarded"
                and not k.lower().startswith(
                    (b"x-forwarded-", b"x-client-", b"x-ssl-", b"x-user-", b"x-role")
                )
            ]
            await self.app(cleaned, receive, wrapped)
        except Exception:
            if sent:
                raise
            logging.getLogger("cve.http").error("internal_error", exc_info=True)
            await problem(500)(scope, receive, wrapped)
        finally:
            if scope["path"].startswith("/api/v1/"):
                WINDOW.record(status, (time.monotonic() - started) * 1000, time.monotonic())
            logging.getLogger("cve.http").info(
                "request",
                extra={
                    "status": status,
                    "duration_ms": round((time.monotonic() - started) * 1000, 3),
                },
            )
            request_id.reset(rtoken)
            correlation_id.reset(ctoken)
