"""Lifecycle, resolution, signal separation and policy boundaries."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from cve_findings.contracts import ExceptionRequest, Policy, Signals
from cve_findings.rules import deadline, lifecycle, priority, resolution
from pydantic import ValidationError

pytestmark = pytest.mark.findings


@pytest.mark.parametrize("state", ["open", "in_progress", "resolved", "closed"])
@pytest.mark.parametrize(
    "technical", ["affected", "potentially_affected", "unknown", "not_applicable", "not_affected"]
)
def test_lifecycle_matrix(state: Any, technical: str) -> None:
    result, reopened = lifecycle(state, technical, qualified_fix=False)
    expected = technical == "affected" and state in {"resolved", "closed"}
    assert reopened == expected
    assert result == ("open" if expected else state)


@pytest.mark.parametrize("state", ["open", "in_progress", "resolved", "closed"])
def test_qualified_fix_never_auto_closes(state: Any) -> None:
    result, reopened = lifecycle(state, "not_affected", qualified_fix=True)
    assert result == ("resolved" if state in {"open", "in_progress"} else state)
    assert not reopened


def proof() -> dict[str, Any]:
    return {
        "captured_at": datetime.now(UTC) - timedelta(seconds=1),
        "is_current": True,
        "run_status": "succeeded",
        "status": "not_affected",
        "result": {
            "data_quality": "complete",
            "coverage": {
                "global_negative": True,
                "sections": {"packages": "complete", "os": "complete"},
            },
            "components": [{"status": "not_affected", "conflicts": []}],
        },
    }


def test_resolution_opt_in_and_complete_current_scope() -> None:
    now = datetime.now(UTC)
    p = Policy(automatic_resolution=True, max_snapshot_age_hours=24)
    assert resolution(proof(), p, now)
    assert not resolution(proof(), Policy(), now)
    changes: list[dict[str, Any]] = [
        {"status": "unknown"},
        {"status": "affected"},
        {"status": "not_applicable"},
        {"is_current": False},
        {"run_status": "failed"},
        {"captured_at": now - timedelta(days=2)},
        {"captured_at": now + timedelta(minutes=5)},
    ]
    for changed in changes:
        assert not resolution(proof() | changed, p, now)
    for result in [
        {"data_quality": "conflicted"},
        {"coverage": {"global_negative": False}},
        {"components": [{"status": "affected"}]},
        {"components": [{"status": "unknown"}]},
        {"components": [{"status": "not_affected", "conflicts": ["conflict"]}]},
    ]:
        value = proof()
        value["result"].update(result)
        assert not resolution(value, p, now)
    value = proof()
    value["result"]["coverage"]["sections"]["packages"] = "partial"
    assert not resolution(value, p, now)


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
def test_priority_uses_valid_cvss(severity: str) -> None:
    result, reasons = priority(
        Signals(cvss={"validation_status": "valid", "calculated_severity": severity}), Policy()
    )
    assert result == severity.lower() and reasons == ["valid_cvss_severity"]


def test_missing_scores_and_kev_separation() -> None:
    assert priority(Signals(), Policy())[0] == "unrated"
    assert (
        priority(
            Signals(
                cvss={"validation_status": "score_mismatch", "calculated_severity": "CRITICAL"}
            ),
            Policy(),
        )[0]
        == "unrated"
    )
    signals = Signals(
        kev_status="present", kev_is_current=True, epss={"score": "0.00001", "is_stale": False}
    )
    assert priority(signals, Policy())[0] == "high"
    assert priority(signals.model_copy(update={"kev_is_current": False}), Policy())[0] == "unrated"


def test_epss_requires_approved_threshold_and_freshness() -> None:
    signals = Signals(epss={"score": "0.9", "is_stale": False})
    assert priority(signals, Policy())[0] == "unrated"
    policy = Policy(epss_high_threshold=Decimal("0.8"))
    assert priority(signals, policy)[0] == "high"
    assert (
        priority(signals.model_copy(update={"epss": {"score": "0.9", "is_stale": True}}), policy)[0]
        == "unrated"
    )


def test_deadline_absence_and_no_silent_extension() -> None:
    start = datetime.now(UTC)
    assert deadline(start, "critical", Policy(), None) is None
    short = Policy(deadlines_hours={"critical": 24})
    old = deadline(start, "critical", short, None)
    assert old == start + timedelta(hours=24)
    assert deadline(start, "critical", Policy(deadlines_hours={"critical": 48}), old) == old
    assert deadline(
        start, "critical", Policy(deadlines_hours={"critical": 12}), old
    ) == start + timedelta(hours=12)
    assert deadline(start, "low", Policy(), old) == old


@pytest.mark.parametrize(
    "bad",
    [
        {"automatic_resolution": True},
        {"deadlines_hours": {"critical": 0}},
        {"epss_high_threshold": "1.1"},
        {"automatic_resolution": True, "max_snapshot_age_hours": 0},
        {"made_up_weight": 17},
    ],
)
def test_invalid_policy(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate(bad)


def test_exception_requires_finite_aware_interval() -> None:
    now = datetime.now(UTC)
    for until in [None, now - timedelta(days=1), now.replace(tzinfo=None)]:
        with pytest.raises(ValidationError):
            ExceptionRequest.model_validate(
                {
                    "reason": "accepted risk",
                    "risk_context": "limited scope",
                    "valid_from": now,
                    "valid_until": until,
                }
            )
