"""Raw protocol attacks are rejected before application models, SQL or state changes."""

from typing import Any

import httpx
import pytest
from cve_api.auth.json_boundary import validate
from cve_api.auth.middleware import AuthBoundary
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

pytestmark = pytest.mark.security


@pytest.mark.parametrize(
    "raw",
    [
        b'{"role":"viewer","role":"admin"}',
        b'{"a":{"id":1,"id":2}}',
        b'{"n":NaN}',
        b'{"n":1e9999}',
        b'{"n":Infinity}',
        b'{"a":"\\ud800"}',
        b'{"\\u0000":"x"}',
        b'{"a":"\\u0000"}',
        b"\xff",
        b"[" * 33 + b"0" + b"]" * 33,
    ],
)
def test_ambiguous_or_resource_hostile_json(raw: bytes) -> None:
    with pytest.raises((ValueError, UnicodeError)):
        validate(raw)


def test_json_string_brackets_and_unicode_remain_valid() -> None:
    validate('{"value":"é [ \\" {", "items":[1,2,3], "empty":null}'.encode())


async def test_gateway_precedes_json_and_models_never_receive_ambiguous_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hits = []

    async def accepted(request: Request) -> JSONResponse:
        hits.append(await request.json())
        return JSONResponse({"ok": True})

    def trusted(_request: Request) -> Any:
        return None

    monkeypatch.setattr("cve_api.auth.middleware.transport", trusted)
    app = Starlette(routes=[Route("/api/v1/status/maintenance", accepted, methods=["POST"])])
    app.add_middleware(AuthBoundary)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    ) as c:
        for raw, media, expected in [
            (b'{"id":1,"id":2}', "application/json", 400),
            (b"{}", "text/plain", 415),
            (b"[" * 33 + b"0" + b"]" * 33, "application/json", 400),
            (b" " * 8193, "application/json", 413),
            (b'{"ok":true}', "application/json", 200),
        ]:
            r = await c.post(
                "/api/v1/status/maintenance", content=raw, headers={"content-type": media}
            )
            assert r.status_code == expected
    assert hits == [{"ok": True}]
