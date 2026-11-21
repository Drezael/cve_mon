"""No risk signal invents technical affectedness; resolution needs full current proof."""

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from cve_findings.contracts import Lifecycle, Policy, Priority, Signals

ORDER = {"unrated": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def priority(signals: Signals, policy: Policy) -> tuple[Priority, list[str]]:
    result: Priority = "unrated"
    reasons = []
    if signals.cvss and signals.cvss.get("validation_status") == "valid":
        severity = str(
            signals.cvss.get("calculated_severity", signals.cvss.get("severity", ""))
        ).lower()
        if severity in {"critical", "high", "medium", "low"}:
            result = severity  # type: ignore[assignment]
            reasons.append("valid_cvss_severity")
    if signals.kev_is_current and signals.kev_status == "present":
        if ORDER[policy.kev_floor] > ORDER[result]:
            result = policy.kev_floor
        reasons.append("current_kev")
    if (
        policy.epss_high_threshold is not None
        and signals.epss
        and not signals.epss.get("is_stale", True)
    ):
        score = signals.epss.get("score")
        if score is not None and Decimal(str(score)) >= policy.epss_high_threshold:
            if ORDER[result] < ORDER["high"]:
                result = "high"
            reasons.append("current_epss_policy_threshold")
    return result, reasons or ["missing_priority_evidence"]


def resolution(match: dict[str, Any], policy: Policy, now: datetime) -> bool:
    if not policy.automatic_resolution or policy.max_snapshot_age_hours is None:
        return False
    captured = match.get("captured_at")
    if (
        not isinstance(captured, datetime)
        or not now - timedelta(hours=policy.max_snapshot_age_hours) <= captured <= now
    ):
        return False
    result = match.get("result", {})
    coverage = result.get("coverage", {})
    sections = coverage.get("sections", {})
    return bool(
        match.get("is_current")
        and match.get("run_status") == "succeeded"
        and match.get("status") == "not_affected"
        and coverage.get("global_negative") is True
        and sections
        and all(v == "complete" for v in sections.values())
        and result.get("data_quality") == "complete"
        and not any(
            c.get("status") != "not_affected" or c.get("conflicts")
            for c in result.get("components", [])
        )
    )


def lifecycle(current: Lifecycle, technical: str, *, qualified_fix: bool) -> tuple[Lifecycle, bool]:
    if technical == "affected" and current in {"resolved", "closed"}:
        return "open", True
    if qualified_fix and current in {"open", "in_progress"}:
        return "resolved", False
    return current, False


def deadline(
    started: datetime, level: Priority, policy: Policy, old: datetime | None
) -> datetime | None:
    hours = policy.deadlines_hours.get(level)
    candidate = started + timedelta(hours=hours) if hours is not None else None
    return min(old, candidate) if old is not None and candidate is not None else old or candidate
