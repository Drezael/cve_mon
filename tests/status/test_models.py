"""State semantics and hostile observations; no healthy-by-absence shortcuts."""

from datetime import UTC, datetime, timedelta

import pytest
from cve_api.status.aggregation import availability, fresh, transition, worst
from cve_api.status.catalog import topological
from cve_api.status.models import Maintenance, Observation
from cve_api.status.probes import backlog
from pydantic import ValidationError


@pytest.mark.parametrize("state", ["healthy", "degraded", "unavailable", "unknown", "starting"])
def test_worst_does_not_average_critical_failure(state: str) -> None:
    assert worst(["healthy", state]) == state
    assert worst([state, "unavailable"]) == "unavailable"


def test_empty_and_stale_are_unknown() -> None:
    now = datetime.now(UTC)
    assert worst([]) == "unknown"
    assert fresh("healthy", None, now, 180) == "unknown"
    assert fresh("healthy", now - timedelta(seconds=181), now, 180) == "unknown"
    assert fresh("healthy", now + timedelta(seconds=1), now, 180) == "unknown"
    assert fresh("healthy", now, now, 180) == "healthy"


def test_confirmed_failure_is_immediate_recovery_requires_two_checks() -> None:
    state, fail, success = transition(
        {"state": "healthy", "failures": 0, "successes": 4}, "unavailable"
    )
    assert (state, fail, success) == ("unavailable", 1, 0)
    state, fail, success = transition(
        {"state": "unavailable", "failures": 1, "successes": 0}, "healthy"
    )
    assert state == "degraded" and success == 1
    assert (
        transition({"state": state, "failures": fail, "successes": success}, "healthy")[0]
        == "healthy"
    )
    assert (
        transition({"state": "unavailable", "failures": 1, "successes": 0}, "unknown")[0]
        == "unknown"
    )


def test_missing_observation_intervals_reduce_coverage() -> None:
    now = datetime.now(UTC)
    values = availability(
        [{"checked_at": now, "result": "healthy"}], now, now + timedelta(seconds=600), 180
    )
    assert values["coverage_percent"] == 30 and values["unknown_seconds"] == 420
    assert availability([], now, now + timedelta(seconds=60), 180)["available_percent"] is None


def test_dag_is_acyclic_and_preserves_real_service_dependencies() -> None:
    order = topological()
    assert order.index("postgres") < order.index("api") < order.index("nginx")
    assert order.index("postfix") < order.index("notification")


@pytest.mark.parametrize(
    "metrics,reason",
    [
        ({}, "EXPECTED_IDLE"),
        ({"queued": 10, "oldest_seconds": 2}, "QUEUE_WITHIN_POLICY"),
        ({"oldest_seconds": 901}, "EXPECTED_PROGRESS_MISSING"),
        ({"expired_leases": 1}, "EXPIRED_LEASE"),
        ({"uncertain": 1}, "SMTP_HANDOFF_UNCERTAIN"),
        ({"capped": 1}, "BACKLOG_SAMPLE_CAPPED"),
        ({"failed": 1}, "RECENT_JOB_FAILURE"),
    ],
)
def test_backlog_obeys_expected_work(metrics: dict[str, int], reason: str) -> None:
    assert backlog("matcher", metrics).reason_code == reason


@pytest.mark.parametrize(
    "metrics", [{"failed": 2}, {"failed": 2, "queued": 1, "oldest_seconds": 3}]
)
def test_worker_queue_keeps_task_failure_history_without_false_outage(
    metrics: dict[str, int],
) -> None:
    result = backlog("jobs", metrics)
    assert result.result == "healthy"
    assert result.metrics["failed"] == 2


@pytest.mark.parametrize(
    "metrics,reason",
    [
        ({"failed": 2, "expired_leases": 1}, "EXPIRED_LEASE"),
        ({"failed": 2, "oldest_seconds": 901}, "EXPECTED_PROGRESS_MISSING"),
        ({"failed": 2, "capped": 1}, "BACKLOG_SAMPLE_CAPPED"),
    ],
)
def test_worker_queue_still_reports_real_obstructions(metrics: dict[str, int], reason: str) -> None:
    result = backlog("jobs", metrics)
    assert result.result == "degraded" and result.reason_code == reason


@pytest.mark.parametrize(
    "metrics",
    [{"token": 1}, {"pending": float("nan")}, {"pending": -1}, {"url": "http://attacker.invalid"}],
)
def test_observation_rejects_secrets_nonfinite_and_free_targets(metrics: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Observation(
            service_id="api",
            check_id="readiness",
            checked_at=datetime.now(UTC),
            result="healthy",
            duration_ms=0,
            reason_code="READY",
            metrics=metrics,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "end,services", [(0, ["api"]), (-1, ["api"]), (91, ["api"]), (1, ["api", "api"])]
)
def test_maintenance_is_finite_and_explicit(end: int, services: list[str]) -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        Maintenance(
            service_ids=services,
            starts_at=now,
            ends_at=now + timedelta(days=end),
            description="Planned maintenance",
            reason="Explicit metadata",
        )


def test_noncritical_outage_and_dependency_cycles(monkeypatch: pytest.MonkeyPatch) -> None:
    from dataclasses import replace

    from cve_api.status import catalog
    from cve_api.status.aggregation import platform

    assert (
        platform(
            [{"state": "healthy", "critical": True}, {"state": "unavailable", "critical": False}]
        )
        == "degraded"
    )
    assert platform([]) == "unknown"
    monkeypatch.setitem(
        catalog.CATALOG, "postgres", replace(catalog.CATALOG["postgres"], dependencies=("api",))
    )
    with pytest.raises(ValueError, match="cycle"):
        catalog.topological()


@pytest.mark.parametrize(
    "age,expected", [(0, "healthy"), (61, "degraded"), (181, "unavailable"), (None, "unknown")]
)
def test_central_consumer_health_uses_actual_contact_even_when_idle(
    age: int | None, expected: str
) -> None:
    from cve_api.status.probes import control_health

    heartbeat = (
        (datetime.now(UTC) - timedelta(seconds=age)).isoformat() if age is not None else None
    )
    workflow, queue = control_health(
        {
            "enabled": True,
            "heartbeat_at": heartbeat,
            "pending": 0,
            "processing": 0,
            "failed": 0,
            "oldest_seconds": 0,
            "expired_leases": 0,
            "capped": False,
        }
    )
    assert workflow.result == expected
    assert queue.result == "healthy"
