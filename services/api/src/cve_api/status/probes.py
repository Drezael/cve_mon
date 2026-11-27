"""Bounded closed-target probes: no redirects, proxy environment or arbitrary response bodies."""

import asyncio
import json
import os
import ssl
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx
from cve_common.config.secrets import read_secret
from pydantic import ValidationError

from cve_api.status.catalog import HTTP_TARGETS
from cve_api.status.models import Observation, Settings, State


def observation(
    service: str,
    check: str,
    result: State,
    reason: str,
    metrics: dict[str, Any] | None = None,
    duration: float = 0,
) -> Observation:
    return Observation(
        service_id=service,
        check_id=check,
        checked_at=datetime.now(UTC),
        result=result,
        reason_code=reason,
        metrics=metrics or {},
        duration_ms=duration,
    )


async def http(
    settings: Settings,
    service: str,
    dimension: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Observation:
    if dimension not in {"liveness", "readiness"}:
        raise ValueError("Unregistered probe dimension")
    start = time.monotonic()
    if service == "nginx":
        base = f"https://cve-nginx:{settings.dashboard_port}"
        path = "/" if dimension == "liveness" else "/api/v1/status/proxy-health"
        ca: Path | None = settings.dashboard_ca
        headers = {"host": settings.dashboard_host}
        if dimension == "readiness":
            headers["x-cve-status-probe"] = read_secret(settings.probe_key_file).get_secret_value()
        extensions: dict[str, Any] = {"sni_hostname": settings.dashboard_host}
    else:
        if service not in HTTP_TARGETS or dimension not in {"liveness", "readiness"}:
            raise ValueError("Unregistered probe")
        base = HTTP_TARGETS[service]
        path = (
            ("/healthz" if dimension == "liveness" else "/healthz/readiness")
            if service == "n8n"
            else "/health/" + ("live" if dimension == "liveness" else "ready")
        )
        if service == "n8n":
            # The API cannot reach the isolated n8n namespace directly.
            base = HTTP_TARGETS["notification"]
            path = "/health/n8n/" + ("live" if dimension == "liveness" else "ready")
        elif service == "notification" and dimension == "readiness":
            path = "/health/worker"
        ca = settings.notification_ca
        headers, extensions = {}, {}
    headers["accept-encoding"] = "identity"
    try:
        if base.startswith("https:") and (ca is None or not ca.is_file()):
            return observation(service, dimension, "unknown", "TLS_TRUST_NOT_CONFIGURED")
        verify: ssl.SSLContext | bool = (
            ssl.create_default_context(cafile=str(ca)) if base.startswith("https:") else True
        )
        async with (
            asyncio.timeout(settings.timeout_seconds),
            httpx.AsyncClient(
                verify=verify,
                transport=transport,
                trust_env=False,
                timeout=settings.timeout_seconds,
                follow_redirects=False,
            ) as client,
            client.stream("GET", base + path, headers=headers, extensions=extensions) as response,
        ):
            if response.headers.get("content-encoding", "identity") != "identity":
                return observation(service, dimension, "unknown", "UNSUPPORTED_ENCODING")
            size = 0
            body = bytearray()
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > 32768:
                    return observation(service, dimension, "unknown", "RESPONSE_TOO_LARGE")
                body.extend(chunk)
            if response.status_code != 200:
                result = "unavailable" if response.status_code in {502, 503, 504} else "unknown"
                reason = "NOT_READY" if result == "unavailable" else "UNEXPECTED_HTTP_STATUS"
            elif service == "nginx" and dimension == "liveness":
                result, reason = (
                    ("healthy", "FRONTEND_RESPONDING")
                    if b"<html" in body.lower()
                    else ("unknown", "INVALID_RESPONSE")
                )
            else:
                value = json.loads(body)
                status = value.get("status") if isinstance(value, dict) else None
                expected = {"alive", "healthy", "ready", "ok"}
                result, reason = (
                    ("healthy", "CHECK_CONFIRMED")
                    if status in expected
                    else ("unknown", "INVALID_RESPONSE")
                )
            return observation(
                service,
                dimension,
                cast(State, result),
                reason,
                duration=(time.monotonic() - start) * 1000,
            )
    except (TimeoutError, httpx.TimeoutException):
        return observation(
            service,
            dimension,
            "unknown",
            "CHECK_TIMEOUT",
            duration=min(60000, (time.monotonic() - start) * 1000),
        )
    except (OSError, httpx.HTTPError, ValueError):
        return observation(
            service,
            dimension,
            "unknown",
            "TRANSPORT_OR_SCHEMA_ERROR",
            duration=min(60000, (time.monotonic() - start) * 1000),
        )


def local(settings: Settings, service: str) -> Observation:
    if service not in {"envoy", "postfix"}:
        raise ValueError("Unregistered local adapter")
    path = settings.reports_dir / service / "observation.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 32768:
                raise ValueError("Bounded regular report required")
            content = source.read(32769)
        if len(content) > 32768:
            raise ValueError("Report too large")
        value = Observation.model_validate_json(content)
        if (
            value.service_id != service
            or value.check_id != "readiness"
            or not 0
            <= (datetime.now(UTC) - value.checked_at).total_seconds()
            <= settings.stale_seconds
        ):
            raise ValueError("Report stale or identity mismatch")
        return value
    except (OSError, ValueError, ValidationError):
        return observation(service, "readiness", "unknown", "LOCAL_ADAPTER_UNAVAILABLE")


def backlog(service: str, metrics: dict[str, Any], limit: int = 900) -> Observation:
    value = {
        k: float(v) if v is not None else None
        for k, v in metrics.items()
        if k
        in {
            "queued",
            "running",
            "retry_pending",
            "failed",
            "expired_leases",
            "oldest_seconds",
            "last_success_age_seconds",
            "heartbeat_age_seconds",
            "completed",
            "pending",
            "uncertain",
            "capped",
            "next_due_seconds",
        }
    }
    if value.get("capped"):
        return observation(service, "backlog", "degraded", "BACKLOG_SAMPLE_CAPPED", value)
    if value.get("expired_leases"):
        return observation(service, "backlog", "degraded", "EXPIRED_LEASE", value)
    if value.get("uncertain"):
        return observation(service, "backlog", "degraded", "SMTP_HANDOFF_UNCERTAIN", value)
    if (value.get("oldest_seconds") or 0) > limit:
        return observation(service, "backlog", "degraded", "EXPECTED_PROGRESS_MISSING", value)
    # Completed task failures describe their individual work, not a broken queue.
    # The shared queue is healthy when it can drain work and has no lost leases.
    # Keep failed counts as diagnostic evidence; do not poison unrelated workers
    # for 24 hours after a source has already recovered successfully.
    if service != "jobs" and value.get("failed"):
        return observation(service, "backlog", "degraded", "RECENT_JOB_FAILURE", value)
    return observation(
        service,
        "backlog",
        "healthy",
        "QUEUE_WITHIN_POLICY"
        if any(value.get(k) for k in ["queued", "running", "pending"])
        else "EXPECTED_IDLE",
        value,
    )


def control_health(data: dict[str, Any]) -> tuple[Observation, Observation]:
    if data.get("sample_stale"):
        return (
            observation("n8n-workflow", "functional", "unknown", "CONTROL_SAMPLE_STALE"),
            observation("n8n-queue", "backlog", "unknown", "CONTROL_SAMPLE_STALE"),
        )
    heartbeat = data.get("heartbeat_at")
    age = (
        max(0, (datetime.now(UTC) - datetime.fromisoformat(heartbeat)).total_seconds())
        if heartbeat
        else None
    )
    state: State = "healthy"
    reason = "CENTRAL_WORKFLOW_ACTIVE"
    if not data["enabled"]:
        state, reason = "unavailable", "CENTRAL_WORKFLOW_DISABLED"
    elif age is None:
        state, reason = "unknown", "CENTRAL_WORKFLOW_NOT_OBSERVED"
    elif age > 180:
        state, reason = "unavailable", "CENTRAL_WORKFLOW_STALLED"
    elif age > 60:
        state, reason = "degraded", "CENTRAL_WORKFLOW_DELAYED"
    workflow = observation(
        "n8n-workflow", "functional", state, reason, {"heartbeat_age_seconds": age}
    )
    queue = backlog("n8n-queue", data, 120)
    return workflow, queue
