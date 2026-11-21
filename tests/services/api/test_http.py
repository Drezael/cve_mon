"""Real ASGI middleware/lifespan, protocol errors and closed business surface."""

import asyncio
from uuid import UUID, uuid4

import httpx
import pytest
from cve_api.factory import create_app
from cve_api.settings import ApiSettings
from fastapi import Request

from tests.services.conftest import no_dependencies

pytestmark = pytest.mark.security


@pytest.mark.parametrize("path", ["/health/live", "/health/ready"])
async def test_technical_health(client: httpx.AsyncClient, path: str) -> None:
    result = await client.get(path)
    assert result.status_code == 200
    assert result.headers["cache-control"] == "no-store"
    UUID(result.headers["x-request-id"])


@pytest.mark.parametrize(
    "path",
    [
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/users",
        "/api/v1/servers",
        "/api/v1/inventories",
        "/api/v1/uploads",
        "/health/live/",
    ],
)
async def test_business_routes_closed(client: httpx.AsyncClient, path: str) -> None:
    result = await client.get(path)
    assert result.status_code == 404
    assert result.json()["code"] == "NOT_FOUND"
    assert result.headers["content-type"].startswith("application/problem+json")


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",
        "cve-api.evil.test",
        "evil.example:8000",
        "cve-api:evil",
        "cve-api:0",
        "cve-api:99999",
        "cve-api:" + "9" * 5000,
        "cve-api:１２３",
    ],
)
async def test_host_rejected(client: httpx.AsyncClient, host: str) -> None:
    assert (
        await client.get("/health/live", headers=[(b"host", host.encode("utf-8"))])
    ).status_code == 400


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
async def test_methods_rejected(client: httpx.AsyncClient, method: str) -> None:
    result = await client.request(method, "/health/live")
    assert result.status_code == 405 and result.json()["status"] == 405


async def test_no_open_cors(client: httpx.AsyncClient) -> None:
    result = await client.options(
        "/health/live",
        headers={"Origin": "https://evil.test", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in result.headers


async def test_parallel_ids_and_untrusted_ids(client: httpx.AsyncClient) -> None:
    ids = [str(uuid4()) for _ in range(15)]
    replies = await asyncio.gather(
        *(
            client.get("/health/live", headers={"X-Request-ID": i, "X-Correlation-ID": i})
            for i in ids
        )
    )
    assert [r.headers["x-request-id"] for r in replies] == ids
    assert [r.headers["x-correlation-id"] for r in replies] == ids
    bad = await client.get("/unknown", headers={"X-Request-ID": "evil-" * 200})
    UUID(bad.json()["request_id"])
    assert "evil-" not in bad.text
    normalized = await client.get("/health/live", headers={"X-Request-ID": uuid4().hex})
    UUID(normalized.headers["x-request-id"])


async def test_header_identity_and_forwarding_are_not_trusted(api_settings: ApiSettings) -> None:
    app = create_app(api_settings, resource_factory=no_dependencies)

    @app.get("/test-scope")
    async def scope(request: Request) -> dict[str, object]:
        return {
            "scheme": request.url.scheme,
            "client": request.client.host if request.client else None,
            "identity": request.headers.get("x-client-verify"),
            "forwarded": request.headers.get("forwarded"),
        }

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://cve-api") as c,
    ):
        r = await c.get(
            "/test-scope",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-For": "1.2.3.4",
                "X-Client-Verify": "SUCCESS",
                "Forwarded": "host=evil.test;proto=https",
            },
        )
        assert r.json() == {
            "scheme": "http",
            "client": "127.0.0.1",
            "identity": None,
            "forwarded": None,
        }


async def test_errors_do_not_reflect_input(api_settings: ApiSettings) -> None:
    app = create_app(api_settings, resource_factory=no_dependencies)

    @app.get("/test-error/{number}")
    async def error(number: int) -> None:
        raise RuntimeError("private-error-marker")

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app, raise_app_exceptions=False),
            base_url="http://cve-api",
        ) as c,
    ):
        for path, code in [("/test-error/private-input-marker", 422), ("/test-error/1", 500)]:
            r = await c.get(path)
            assert r.status_code == code
            assert "private-" not in r.text and "Traceback" not in r.text
            assert r.json()["request_id"] == r.headers["x-request-id"]


async def test_error_envelope_matches_original_contract(api_settings: ApiSettings) -> None:
    from pathlib import Path

    import yaml
    from cve_common.http.errors import ServiceError
    from jsonschema import Draft202012Validator, FormatChecker

    document = yaml.safe_load(
        (Path(__file__).resolve().parents[3] / "contracts/api/openapi.yaml").read_text()
    )
    schema = document["components"]["schemas"]["Problem"]
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    app = create_app(api_settings, resource_factory=no_dependencies)

    @app.get("/test-controlled/{status}")
    async def controlled(status: int) -> None:
        raise ServiceError(status)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://cve-api") as current,
    ):
        for status in (400, 401, 403, 404, 409, 413, 429, 503, 500):
            response = await current.get("/test-controlled/" + str(status))
            assert response.status_code == status
            validator.validate(response.json())
            assert response.headers["x-correlation-id"]


async def test_duplicate_host_and_correlation_headers(client: httpx.AsyncClient) -> None:
    result = await client.get("/health/live", headers=[("host", "cve-api"), ("host", "evil.test")])
    assert result.status_code == 400
    result = await client.get("/health/live", headers={"x-correlation-id": "unsafe-" * 100})
    UUID(result.headers["x-correlation-id"])
    assert "unsafe-" not in result.text
