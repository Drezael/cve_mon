"""Closed destinations, bounded schemas, HTTP faults and stale local reports."""

import json
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cve_api.status.models import Settings
from cve_api.status.probes import http, local
from cve_common.config.settings import DatabaseSettings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    key = tmp_path / "probe.key"
    key.write_text("synthetic-status-fixture-key-for-probe-only")
    key.chmod(0o600)
    ca = Path(ssl.get_default_verify_paths().cafile or "/etc/ssl/certs/ca-certificates.crt")
    return Settings(
        app_env="test",
        database=DatabaseSettings(
            host="cve-postgres", username="status_probe", password_file=key, ca_file=ca
        ),
        reports_dir=tmp_path,
        dashboard_ca=ca,
        notification_ca=ca,
        probe_key_file=key,
        dashboard_host="dashboard.example.test",
    )


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (200, {"status": "ready"}, "healthy"),
        (503, {"status": "not-ready"}, "unavailable"),
        (302, {}, "unknown"),
        (200, {"password": "do-not-copy"}, "unknown"),  # pragma: allowlist secret
        (200, [], "unknown"),
    ],
)
async def test_http_classification_and_no_arbitrary_body(
    settings: Settings, status: int, body: object, expected: str
) -> None:
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(status, json=body, headers={"location": "http://169.254.169.254/"})

    result = await http(settings, "api", "readiness", transport=httpx.MockTransport(handler))
    assert result.result == expected and len(requests) == 1
    assert (
        "password" not in result.model_dump_json() and "do-not-copy" not in result.model_dump_json()
    )
    assert str(requests[0].url) == "http://127.0.0.1:8000/health/ready"


async def test_timeout_and_large_response(settings: Settings) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("sanitized", request=request)

    result = await http(settings, "api", "readiness", transport=httpx.MockTransport(timeout))
    assert result.result == "unknown" and result.reason_code == "CHECK_TIMEOUT"
    result = await http(
        settings,
        "api",
        "readiness",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 32769)),
    )
    assert result.result == "unknown" and result.reason_code == "RESPONSE_TOO_LARGE"


@pytest.mark.parametrize(
    "service", ["http://169.254.169.254", "file:///etc/passwd", "attacker.invalid", "postgres"]
)
async def test_no_free_probe_target(settings: Settings, service: str) -> None:
    with pytest.raises(ValueError, match="Unregistered"):
        await http(settings, service, "readiness")


def test_local_report_freshness_identity_and_no_secrets(settings: Settings) -> None:
    folder = settings.reports_dir / "postfix"
    folder.mkdir()
    path = folder / "observation.json"
    body = {
        "schema_version": 1,
        "service_id": "postfix",
        "check_id": "readiness",
        "checked_at": datetime.now(UTC).isoformat(),
        "result": "healthy",
        "duration_ms": 1,
        "reason_code": "LOCAL_READINESS_CONFIRMED",
        "metrics": {"queue_size": 0},
    }
    path.write_text(json.dumps(body))
    assert local(settings, "postfix").result == "healthy"
    body["checked_at"] = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    path.write_text(json.dumps(body))
    assert local(settings, "postfix").result == "unknown"
    body["checked_at"] = datetime.now(UTC).isoformat()
    body["metrics"] = {"recipient_email": 1}
    path.write_text(json.dumps(body))
    assert local(settings, "postfix").result == "unknown"


def test_local_adapter_cannot_follow_symlinks_or_block_on_special_files(settings: Settings) -> None:
    import os

    folder = settings.reports_dir / "envoy"
    folder.mkdir()
    path = folder / "observation.json"
    path.symlink_to(settings.probe_key_file)
    assert local(settings, "envoy").result == "unknown"
    path.unlink()
    os.mkfifo(path)
    assert local(settings, "envoy").result == "unknown"
    path.unlink()
    path.write_bytes(b"x" * 32769)
    assert local(settings, "envoy").result == "unknown"


async def test_n8n_health_uses_fixed_bridge_and_notification_uses_worker(
    settings: Settings,
) -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"status": "ready"})

    transport = httpx.MockTransport(handler)
    assert (await http(settings, "n8n", "readiness", transport=transport)).result == "healthy"
    assert (
        await http(settings, "notification", "readiness", transport=transport)
    ).result == "healthy"
    assert seen == [
        "https://cve-notification:8000/health/n8n/ready",
        "https://cve-notification:8000/health/worker",
    ]


@pytest.mark.parametrize(
    "body,status,expected",
    [
        ({"status": "ok"}, 200, "ready"),
        ({"status": "ok"}, 503, "not_ready"),
        ({"unexpected": "value"}, 200, "unknown"),
        ("x" * 5000, 200, "unknown"),
    ],
)
async def test_health_bridge_is_bounded_and_does_not_forward_bodies(
    settings: Settings, body: object, status: int, expected: str
) -> None:
    from cve_notification.health import n8n_probe

    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(status, json=body)

    result = await n8n_probe(settings.dashboard_ca, "ready", transport=httpx.MockTransport(handler))
    assert json.loads(bytes(result.body)) == {"status": expected}
    assert seen == ["https://cve-n8n:5678/healthz/readiness"]
