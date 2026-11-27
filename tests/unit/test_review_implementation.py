"""Behavioral regressions from the repository review; no external services required."""

import asyncio
import json
import logging
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from cve_api.auth.service import AuthService
from cve_api.status.cache import StatusCache
from cve_api.status.probes import control_health
from cve_api.users.schemas import UserCreate, UserPatch
from cve_common.config.settings import DatabaseSettings
from cve_common.events.delivery import Delivery, DeliveryRepository, Dispatcher
from cve_common.http.errors import install_handlers
from cve_common.jobs.contracts import Payload
from cve_common.jobs.models import Job
from cve_common.jobs.registry import JobDefinition, Registry
from cve_common.jobs.worker import Worker, WorkerSettings
from cve_common.lifecycle.tasks import LoopHealth, drain_tasks
from cve_common.logging.setup import JSONFormatter
from cve_common.smtp_settings import SMTPConfig
from cve_notification.rules import address
from fastapi import FastAPI
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.exc import SQLAlchemyError


def test_csrf_stable_for_session_and_changes_with_cookie_and_gateway() -> None:
    service = object.__new__(AuthService)
    service.gateway = secrets.token_urlsafe(32)
    cookie = secrets.token_urlsafe(32)
    value = service.session_csrf(cookie)
    assert len(value) == 43 and service.session_csrf(cookie) == value
    assert service.session_csrf(secrets.token_urlsafe(32)) != value
    service.gateway = secrets.token_urlsafe(32)
    assert service.session_csrf(cookie) != value


def settings(tmp_path: Path) -> WorkerSettings:
    return WorkerSettings(
        app_env="test",
        service_name="cve-review",
        concurrency=1,
        heartbeat_seconds=0.05,
        lease_seconds=0.3,
        database=DatabaseSettings(
            host="cve-postgres",
            username="importer",
            password_file=tmp_path / "secret",
            ca_file=tmp_path / "ca",
        ),
    )


@pytest.mark.parametrize("error", [TimeoutError, OSError, SQLAlchemyError])
async def test_dispatcher_cancels_transport_after_heartbeat_error(
    tmp_path: Path,
    error: type[Exception],
) -> None:
    class Repository:
        async def heartbeat(self, *_args: Any) -> bool:
            raise error()

    runtime = Dispatcher(cast(DeliveryRepository, Repository()), settings(tmp_path), {})
    runtime.healthy = True
    transport = asyncio.create_task(asyncio.sleep(10))
    await runtime._heartbeat(cast(Delivery, None), transport)
    await asyncio.gather(transport, return_exceptions=True)
    assert transport.cancelled() and not runtime.healthy


async def test_worker_never_logs_success_after_rejected_finish(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class Input(Payload):
        pass

    async def handler(_context: Any, _input: BaseModel) -> None:
        pass

    registry = Registry()
    registry.register(JobDefinition("review.test", 1, Input, None, handler, 2))
    outcomes = []

    class Repository:
        async def heartbeat(self, *_args: Any) -> bool:
            return True

        async def finish(self, _job: Job, outcome: str, *_args: Any, **_kwargs: Any) -> bool:
            outcomes.append(outcome)
            return False

    repo = Repository()
    repo.registry = registry  # type: ignore[attr-defined]
    job = Job(
        id=uuid4(),
        correlation_id=uuid4(),
        job_type="review.test",
        payload_version=1,
        payload={},
        status="running",
        attempts=1,
        max_attempts=3,
        fencing_token=1,
    )
    runtime = Worker(repo, settings(tmp_path))  # type: ignore[arg-type]
    with caplog.at_level(logging.INFO):
        await runtime.execute(job, asyncio.Event())
    assert outcomes == ["succeeded"]
    assert any(getattr(r, "error_code", None) == "LEASE_LOST" for r in caplog.records)
    assert not any(r.msg == "job_finished" for r in caplog.records)


def test_missing_and_stale_control_samples_never_claim_healthy_zero_queue() -> None:
    cache = StatusCache()
    empty = cache.read_control()
    assert empty["pending"] is None and control_health(empty)[1].result == "unknown"
    cache.set_control({"enabled": True, "pending": 10})
    cache.control_checked_at = datetime.now(UTC) - timedelta(seconds=181)
    sample = cache.read_control()
    assert sample["pending"] == 10 and sample["sample_stale"]
    assert all(o.result == "unknown" for o in control_health(sample))


@pytest.mark.parametrize("value", ["Test@EXAMPLE.ORG", "a+b@example.org", " test@example.org "])
def test_account_and_mail_share_normalization(value: str) -> None:
    user = UserCreate(username="review", display_name="Review", email=value)
    assert user.email == SMTPConfig.address(value)
    assert address(value, ["example.org"])
    assert UserPatch(version=1, reason="review", email=value).email == user.email


@pytest.mark.parametrize(
    "value", ["test@example.c", "a..b@example.org", "a@bad..org", "a@-bad.org"]
)
def test_invalid_mailbox_rejected_at_account_boundary(value: str) -> None:
    with pytest.raises(ValidationError):
        UserCreate(username="review", display_name="Review", email=value)
    assert not address(value, [])


async def test_validation_exposes_declared_field_without_value_or_validator_text() -> None:
    class Input(BaseModel):
        count: int = Field(ge=1)

    app = FastAPI()
    install_handlers(app)

    @app.post("/")
    async def endpoint(body: Input) -> None:
        pass

    secret = secrets.token_urlsafe(32)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        response = await c.post("/", json={"count": secret})
    assert response.status_code == 422
    assert response.json()["errors"] == [{"pointer": "/body/count", "message": "Invalid value"}]
    assert secret not in response.text


async def test_background_failure_does_not_prevent_other_tasks_draining() -> None:
    finished = False

    async def failed() -> None:
        raise ValueError("controlled failure")

    async def other() -> None:
        nonlocal finished
        await asyncio.sleep(0.01)
        finished = True

    task = asyncio.create_task(failed())
    other_task = asyncio.create_task(other())
    with pytest.raises(ValueError):
        await drain_tasks(task, other_task)
    health = LoopHealth()
    health.tick()
    assert finished and not health.ready(task, 10)


def test_lock_mode_reaches_structured_log() -> None:
    record = logging.LogRecord(
        "cve.auth.locks", logging.INFO, __file__, 1, "security_lock_acquired", (), None
    )
    record.mutation = False
    record.wait_seconds = 0.25
    value = json.loads(JSONFormatter("review").format(record))
    assert value["mutation"] is False and value["wait_seconds"] == 0.25


async def test_dispatcher_does_not_report_rejected_ack_as_delivered(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    event = SimpleNamespace(event_id=uuid4(), correlation_id=uuid4())
    repo = SimpleNamespace(
        event=AsyncMock(return_value=event),
        heartbeat=AsyncMock(return_value=True),
        finish=AsyncMock(return_value=False),
    )
    delivery = Delivery(
        event_id=event.event_id,
        destination="test",
        attempts=1,
        lease_owner=uuid4(),
        lease_token=uuid4(),
        fencing_token=1,
    )
    dispatcher = Dispatcher(
        cast(DeliveryRepository, repo), settings(tmp_path), {"test": AsyncMock()}
    )
    with caplog.at_level(logging.INFO):
        await dispatcher.execute(delivery)
    repo.finish.assert_awaited_once_with(delivery, "delivered")
    assert not any(r.msg == "delivery_finished" for r in caplog.records)
    assert any(getattr(r, "error_code", None) == "LEASE_LOST" for r in caplog.records)


async def test_smtp_model_maximum_recipients_reaches_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cve_api.auth.middleware import AuthBoundary
    from cve_common.smtp_settings import SMTPUpdate

    app = FastAPI()
    app.add_middleware(AuthBoundary)
    monkeypatch.setattr("cve_api.auth.middleware.transport", lambda _request: None)

    @app.put("/api/v1/dashboard/administration/smtp")
    async def save(body: SMTPUpdate) -> dict[str, int]:
        return {"count": len(body.recipients)}

    body = SMTPUpdate(version=0, recipients=[f"user{i}@example.org" for i in range(1000)])
    assert len(body.model_dump_json()) > 8192
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    ) as c:
        response = await c.put(
            "/api/v1/dashboard/administration/smtp", json=body.model_dump(mode="json")
        )
    assert response.status_code == 200 and response.json() == {"count": 1000}


@pytest.mark.parametrize("status,hours", [("closed", -1), ("resolved", -1), ("open", 49)])
async def test_deadline_rechecks_locked_finding_state(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    hours: int,
) -> None:
    from cve_findings.contracts import Request
    from cve_findings.service import Service

    now = datetime.now(UTC)
    identity = uuid4()
    monkeypatch.setattr(
        "cve_findings.service.active_policy",
        AsyncMock(return_value=(uuid4(), SimpleNamespace(deadline_warning_hours=24))),
    )
    monkeypatch.setattr("cve_findings.service.rows", AsyncMock(return_value=[{"id": identity}]))
    monkeypatch.setattr(
        "cve_findings.service.one",
        AsyncMock(
            return_value={"id": identity, "status": status, "due_at": now + timedelta(hours=hours)}
        ),
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(scalar_one=lambda: now))
    )
    service = Service(cast(Any, None))
    result = await service.deadlines(cast(Any, session), cast(Any, SimpleNamespace()), Request())
    assert result.count == 0
    assert all("SELECT clock_timestamp()" in str(c.args[0]) for c in session.execute.call_args_list)


async def test_invalid_report_preferences_do_not_block_next_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cve_notification import reports

    bad, good, owner = uuid4(), uuid4(), uuid4()
    pending = [
        {"id": ident, "user_id": ident, "origin": "manual", "correlation_id": uuid4()}
        for ident in (bad, good)
    ]
    monkeypatch.setattr(reports, "rows", AsyncMock(return_value=pending))
    monkeypatch.setattr(reports, "busy", AsyncMock(return_value=None))
    monkeypatch.setattr(reports, "insert", AsyncMock(return_value=uuid4()))

    async def one(_session: Any, sql: str, **params: Any) -> dict[str, Any]:
        if "FROM security.users" in sql:
            return {
                "id": params["id"],
                "status": "active",
                "email": "test@example.org",
                "mail_config": None,
                "config": {"timezone": None} if params["id"] == bad else {},
            }
        return {"id": owner}

    monkeypatch.setattr(reports, "one", one)
    session = SimpleNamespace(execute=AsyncMock())
    assert await reports.maintain(cast(Any, session), uuid4()) == 1
    mutations = [
        (str(c.args[0]), c.args[1]) for c in session.execute.call_args_list if len(c.args) > 1
    ]
    assert any(
        "invalid_recipient_preferences" in sql and params["id"] == bad for sql, params in mutations
    )
    assert any("state='ready'" in sql and params["id"] == good for sql, params in mutations)


async def test_erasure_status_is_owner_scoped_and_completed_replay_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hashlib

    from scripts.automation_executor import agent

    monkeypatch.setattr(agent, "directory", lambda _config: tmp_path)
    identity, actor, server = uuid4(), uuid4(), uuid4()
    directory = tmp_path / "erase-receipts"
    directory.mkdir()
    binding = hashlib.sha256(
        json.dumps(
            {"server": str(server), "actor": str(actor), "version": 7}, sort_keys=True
        ).encode()
    ).hexdigest()
    (directory / (str(identity) + ".json")).write_text(
        json.dumps({"actor_id": str(actor), "binding": binding, "state": "completed"})
    )
    request = {
        "request_id": str(identity),
        "actor_id": str(actor),
        "server_id": str(server),
        "version": 7,
    }
    assert agent.erasure_status(cast(Any, None), request) == {"status": 200, "state": "completed"}
    assert agent.erasure_status(cast(Any, None), request | {"actor_id": str(uuid4())}) == {
        "status": 404
    }
    assert agent.erase(cast(Any, None), request) == {"status": 204}
    assert agent.erase(cast(Any, None), request | {"version": 8}) == {"status": 409}
