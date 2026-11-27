"""Deterministic policy decisions, UTC digest intervals and bounded DST-safe deferral."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from zoneinfo import ZoneInfo

from cve_common.email_address import normalize_address

from cve_notification.contracts import Preferences, Quiet, Rule

ORDER = {"unrated": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def address(value: str, domains: list[str]) -> bool:
    try:
        normalized = normalize_address(value)
    except ValueError:
        return False
    return not domains or normalized.rsplit("@", 1)[1] in domains


def applies(rule: Rule, event: str, finding: dict[str, Any]) -> bool:
    basis = finding.get("priority_basis") or {}
    cvss = basis.get("cvss") or {}
    epss = basis.get("epss") or {}
    return bool(
        rule.enabled
        and event in rule.event_types
        and ORDER[finding["current_priority"]] >= ORDER[rule.minimum_priority]
        and (not rule.lifecycle or finding["status"] in rule.lifecycle)
        and (not rule.technical or finding["latest_matching_status"] in rule.technical)
        and (
            not rule.kev_only
            or basis.get("kev_is_current")
            and basis.get("kev_status") == "present"
        )
        and (
            rule.minimum_cvss is None
            or cvss.get("validation_status") == "valid"
            and cvss.get("calculated_score") is not None
            and Decimal(str(cvss["calculated_score"])) >= rule.minimum_cvss
        )
        and (
            rule.minimum_epss is None
            or not epss.get("is_stale", True)
            and epss.get("score") is not None
            and Decimal(str(epss["score"])) >= rule.minimum_epss
        )
    )


def preference_reason(
    rule: Rule, prefs: Preferences, event: str, finding: dict[str, Any]
) -> str | None:
    if rule.suppress_active_exception and finding.get("has_active_exception"):
        return "approved_exception_policy"
    if not rule.mandatory and (
        not prefs.enabled
        or event not in prefs.event_types
        or ORDER[finding["current_priority"]] < ORDER[prefs.minimum_priority]
    ):
        return "user_preference"
    return None


def next_allowed(now: datetime, quiet: Quiet | None) -> datetime:
    if quiet is None:
        return now
    # Iterate actual UTC minutes: both folds and nonexistent local times are unambiguous.
    zone = ZoneInfo(quiet.timezone)
    for minute in range(8 * 24 * 60):
        candidate = now + timedelta(minutes=minute)
        local = candidate.astimezone(zone)
        wall = local.time().replace(tzinfo=None)
        if quiet.start < quiet.end:
            blocked = local.weekday() in quiet.weekdays and quiet.start <= wall < quiet.end
        else:
            blocked = (local.weekday() in quiet.weekdays and wall >= quiet.start) or (
                (local.weekday() - 1) % 7 in quiet.weekdays and wall < quiet.end
            )
        if not blocked:
            return candidate
    raise ValueError("Quiet time has no bounded release")


def window(now: datetime, hours: int) -> tuple[datetime, datetime]:
    seconds = hours * 3600
    start = datetime.fromtimestamp(int(now.timestamp()) // seconds * seconds, UTC)
    return start, start + timedelta(seconds=seconds)
