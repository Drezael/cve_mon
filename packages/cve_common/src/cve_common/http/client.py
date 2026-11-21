"""Explicit destinations and TLS verification; no environment or redirect fallback."""

import re
import ssl
from collections.abc import Collection, Mapping
from typing import Any

import httpx

from cve_common.logging.correlation import correlation_id, request_id


class ServiceClient:
    def __init__(
        self,
        origins: Mapping[str, str],
        *,
        proxy: str | None = None,
        external: bool = False,
        ca_file: str | None = None,
        timeout: float = 2,
        internal_hosts: Collection[str] = (),
    ) -> None:
        if not origins or not 0 < timeout <= 30:
            raise ValueError("Explicit destinations and bounded timeout required")
        if proxy is not None:
            raise ValueError("Outbound proxies are not supported; use direct verified HTTPS")
        self.origins = {name: httpx.URL(url) for name, url in origins.items()}
        if any(not re.fullmatch(r"cve-[a-z][a-z0-9-]{0,47}", host) for host in internal_hosts):
            raise ValueError("Explicit Docker service identities required")
        for url in self.origins.values():
            if not external and url.host not in {
                "cve-api",
                "cve-dashboard",
                "cve-service-status",
                "localhost",
                "127.0.0.1",
                *internal_hosts,
            }:
                raise ValueError("Explicit internal service origin required")
            if (
                url.username
                or url.password
                or url.query
                or url.fragment
                or url.path not in ("", "/")
            ):
                raise ValueError("Origin only; no credentials or path")
            if url.scheme not in ({"https"} if external else {"http", "https"}):
                raise ValueError("Verified HTTPS required externally")
        self.client = httpx.AsyncClient(
            verify=ssl.create_default_context(cafile=ca_file),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    async def request(
        self,
        method: str,
        destination: str,
        path: str = "/",
        *,
        json: dict[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        origin = self.origins[destination]
        if (
            not path.startswith("/")
            or path.startswith("//")
            or "\\" in path
            or any(c in path for c in "\r\n\0")
        ):
            raise ValueError("Relative absolute path required")
        url = origin.copy_with(raw_path=path.encode("ascii"))
        outgoing = dict(headers or {})
        if request_id.get():
            outgoing["X-Request-ID"] = str(request_id.get())
        if correlation_id.get():
            outgoing["X-Correlation-ID"] = str(correlation_id.get())
        return await self.client.request(method, url, headers=outgoing, json=json)

    async def close(self) -> None:
        await self.client.aclose()
