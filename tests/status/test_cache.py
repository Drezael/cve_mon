"""Live cache stays readable through persistence failures and cannot hide stale checks."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest
from cve_api.status.cache import StatusCache
from cve_api.status.catalog import CATALOG
from cve_api.status.collector import Collector
from cve_api.status.models import Collect, Observation, Settings
from cve_api.status.router import states
from cve_common.config.settings import DatabaseSettings
from cve_common.jobs.execution import ExecutionContext
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request


def observations() -> list[Observation]:
    return [
        Observation(
            service_id=key,
            check_id="readiness",
            checked_at=datetime.now(UTC),
            result="healthy",
            duration_ms=1,
            reason_code="CHECK_CONFIRMED",
        )
        for key in CATALOG
    ]


def test_cache_is_bounded_isolated_and_rejects_old_observations() -> None:
    cache = StatusCache()
    values = observations()
    cache.publish(values)
    timestamp = cache.current["api"]["observed_at"]
    for _ in range(100):
        result = cache.rows()
        next(v for v in result if v["id"] == "api")["state"] = "unavailable"
    assert cache.current["api"]["state"] == "healthy"
    assert cache.current["api"]["observed_at"] == timestamp
    cache.publish(
        [
            values[0].model_copy(
                update={"checked_at": timestamp - timedelta(seconds=200), "result": "unavailable"}
            )
        ]
    )
    assert cache.current["api"]["observed_at"] == timestamp
    for number in range(2100):
        cache.publish(
            [
                Observation(
                    service_id="api",
                    check_id="readiness",
                    checked_at=datetime.now(UTC),
                    result="unavailable" if number % 2 else "healthy",
                    duration_ms=1,
                    reason_code="CHECK_CONFIRMED",
                )
            ]
        )
    assert len(cache.samples["api", "readiness"]) == 2000
    assert len(cache.history["api"]) <= 512


def test_missing_diagnostics_do_not_erase_confirmed_service_readiness() -> None:
    cache = StatusCache()
    cache.publish(
        observations()
        + [
            Observation(
                service_id="api",
                check_id="backlog",
                checked_at=datetime.now(UTC),
                result="unknown",
                duration_ms=0,
                reason_code="DATABASE_SAMPLE_UNAVAILABLE",
            )
        ]
    )
    assert cache.current["api"]["state"] == "healthy"
    assert next(v for v in cache.checks("api") if v["check_id"] == "backlog")["result"] == "unknown"


async def test_http_status_reads_cached_measurements_without_status_sql(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = StatusCache()
    cache.publish(observations())
    cache.set_control(
        {
            "enabled": True,
            "heartbeat_at": datetime.now(UTC).isoformat(),
            "pending": 0,
            "processing": 0,
            "paused": 0,
            "failed": 0,
            "oldest_seconds": 0,
            "expired_leases": 0,
            "capped": False,
        }
    )
    app = SimpleNamespace(state=SimpleNamespace(status_collector=SimpleNamespace(cache=cache)))
    request = Request({"type": "http", "app": app})

    async def metadata(_session: Any, sql: str, **_values: Any) -> list[dict[str, Any]]:
        assert (
            "maintenance_windows" in sql
        )  # Current states and queue samples never hit PostgreSQL.
        return []

    monkeypatch.setattr("cve_api.status.router.rows", metadata)
    result = await states(None, request)
    assert len(result) == 23 and all(v["state"] == "healthy" for v in result)
    cache.current["api"]["observed_at"] = datetime.now(UTC) - timedelta(seconds=181)
    again = await states(None, request)
    assert next(v for v in again if v["id"] == "api")["state"] == "unknown"
    assert next(v for v in again if v["id"] == "postgres")["state"] == "healthy"


async def test_cache_survives_failed_completion_and_retries_only_incident_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = Collector(
        Settings(
            app_env="test",
            database=DatabaseSettings(
                host="cve-postgres",
                username="status_probe",
                password_file=tmp_path / "secret",
                ca_file=tmp_path / "ca",
            ),
            reports_dir=tmp_path,
            probe_key_file=tmp_path / "probe",
            dashboard_ca=tmp_path / "ca",
            dashboard_host="dashboard.example.test",
        )
    )

    async def gather() -> list[Observation]:
        return observations()

    monkeypatch.setattr(value, "gather", gather)

    async def failed(_save: Any) -> None:
        raise SQLAlchemyError("Unavailable incident persistence")

    context = SimpleNamespace(job=SimpleNamespace(correlation_id=uuid4()), complete=failed)
    with pytest.raises(SQLAlchemyError):
        await value.handle(cast(ExecutionContext, context), Collect())
    assert len(value.cache.current) == len(CATALOG) and value.pending_incidents
    assert all(v["state"] == "healthy" for v in value.cache.current.values())
    calls: list[str] = []

    async def execute(_session: Any, sql: str, **_values: Any) -> None:
        assert "status.current_states" not in sql and "status.check_observations" not in sql
        calls.append(sql)

    async def incident(*_args: Any, **_kwargs: Any) -> None:
        pass

    async def completed(save: Any) -> None:
        await save(None)

    monkeypatch.setattr("cve_api.status.collector.execute", execute)
    monkeypatch.setattr(value, "incident", incident)
    context.complete = completed
    await value.handle(cast(ExecutionContext, context), Collect())
    assert not value.pending_incidents and calls
    calls.clear()
    await value.handle(cast(ExecutionContext, context), Collect())
    assert not calls  # Stable periodic measurements have no status-table writes.
