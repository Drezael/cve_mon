"""Verify the private ingress gate and bound bodies before JSON/Pydantic processing."""

import asyncio
import re

from cve_common.http.responses import problem
from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from .dependencies import transport
from .errors import AuthError
from .json_boundary import validate


class AuthBoundary:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith(
            ("/api/v1/auth/", "/api/v1/dashboard/", "/api/v1/findings", "/api/v1/status/")
        ):
            await self.app(scope, receive, send)
            return
        try:
            transport(Request(scope))
        except AuthError as error:
            await problem(error.status)(scope, receive, send)
            return
        if scope["path"] == "/api/v1/dashboard/inventories/upload":
            await self.app(scope, receive, send)
            return
        large = bool(
            re.fullmatch(
                r"/api/v1/dashboard/(?:admin/server-access/[0-9a-f-]{36}|notifications/(?:templates|rules(?:/[0-9a-f-]{36})?)|administration/templates/preview)",
                scope["path"],
            )
        )
        maximum = 32768 if large else 8192
        chunks = []
        size = 0
        try:
            async with asyncio.timeout(5):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    data = message.get("body", b"")
                    size += len(data)
                    if size > maximum:
                        await problem(413)(scope, receive, send)
                        return
                    chunks.append(data)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            await problem(400)(scope, receive, send)
            return
        body = b"".join(chunks)
        if body:
            headers = Request(scope).headers
            content_type = headers.getlist("content-type")
            encoding = headers.getlist("content-encoding")
            if len(content_type) != 1 or encoding not in ([], ["identity"]):
                await problem(415)(scope, receive, send)
                return
            media = content_type[0].split(";", 1)[0].strip().lower()
            if media != "application/json":
                await problem(415)(scope, receive, send)
                return
            try:
                validate(body)
            except (ValueError, UnicodeError, RecursionError):
                await problem(400)(scope, receive, send)
                return

        async def bounded_receive() -> dict[str, object]:
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, bounded_receive, send)
