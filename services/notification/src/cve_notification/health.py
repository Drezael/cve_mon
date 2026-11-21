"""Fixed health-only n8n bridge across the existing private network boundary."""

import json
import ssl
from pathlib import Path
from typing import Literal

import httpx
from starlette.responses import JSONResponse


async def n8n_probe(
    ca: Path,
    dimension: Literal["live", "ready"],
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> JSONResponse:
    path = "/healthz" if dimension == "live" else "/healthz/readiness"
    try:
        context = ssl.create_default_context(cafile=str(ca))
        async with (
            httpx.AsyncClient(
                verify=context,
                trust_env=False,
                timeout=1.5,
                follow_redirects=False,
                transport=transport,
            ) as client,
            client.stream(
                "GET", "https://cve-n8n:5678" + path, headers={"accept-encoding": "identity"}
            ) as upstream,
        ):
            if upstream.status_code != 200:
                return JSONResponse({"status": "not_ready"}, status_code=503)
            if upstream.headers.get("content-encoding", "identity") != "identity":
                raise ValueError("unsupported_encoding")
            body = bytearray()
            async for part in upstream.aiter_bytes():
                body.extend(part)
                if len(body) > 4096:
                    raise ValueError("health_response_limit")
            value = json.loads(body)
            if not isinstance(value, dict) or value.get("status") not in {"ok", "ready", "alive"}:
                raise ValueError("invalid_health_response")
        return JSONResponse({"status": "alive" if dimension == "live" else "ready"})
    except (OSError, TimeoutError, ValueError, httpx.HTTPError):
        return JSONResponse({"status": "unknown"})
