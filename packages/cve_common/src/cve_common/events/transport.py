"""Only private operator-defined HTTPS destinations; bearer credentials never enter events."""

import re
from pathlib import Path

import httpx
from pydantic import Field, field_validator

from cve_common.config.secrets import read_secret
from cve_common.events.contracts import EventEnvelope
from cve_common.http.client import ServiceClient
from cve_common.jobs.contracts import Payload
from cve_common.jobs.errors import ErrorCode, JobError
from cve_common.logging.redaction import register_secret


class Target(Payload):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,47}$")
    origin: str
    path: str = Field(default="/events", max_length=256)
    token_file: Path = Field(repr=False)
    ca_file: Path
    timeout: float = Field(default=2, gt=0, le=10)

    @field_validator("origin")
    @classmethod
    def allowed_origin(cls, value: str) -> str:
        url = httpx.URL(value)
        if url.scheme != "https" or not re.fullmatch(r"cve-[a-z][a-z0-9-]{0,47}", url.host or ""):
            raise ValueError("Explicit internal Docker HTTPS identity required")
        if url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValueError("Origin only, without credentials")
        return str(url).rstrip("/")

    @field_validator("path")
    @classmethod
    def relative_path(cls, value: str) -> str:
        if not re.fullmatch(r"/[a-zA-Z0-9/_-]{0,255}", value) or value.startswith("//"):
            raise ValueError("Explicit relative path required")
        return value


class HTTPTransport:
    def __init__(self, target: Target) -> None:
        self.target = target
        secret = read_secret(target.token_file)
        register_secret(secret)
        self._authorization = "Bearer " + secret.get_secret_value()
        self.client = ServiceClient(
            {"target": target.origin},
            internal_hosts={str(httpx.URL(target.origin).host)},
            ca_file=str(target.ca_file),
            timeout=target.timeout,
        )

    async def send(self, event: EventEnvelope) -> None:
        response = await self.client.request(
            "POST",
            "target",
            self.target.path,
            json=event.model_dump(mode="json"),
            headers={
                "Authorization": self._authorization,
                "Idempotency-Key": str(event.event_id),
                "X-Correlation-ID": str(event.correlation_id),
            },
        )
        if 200 <= response.status_code < 300:
            return
        if response.status_code == 429:
            raise JobError(ErrorCode.RATE_LIMIT)
        if response.status_code >= 500:
            raise JobError(ErrorCode.UNAVAILABLE)
        if response.status_code in (401, 403):
            raise JobError(ErrorCode.FORBIDDEN)
        raise JobError(ErrorCode.PERMANENT)

    async def close(self) -> None:
        await self.client.close()
