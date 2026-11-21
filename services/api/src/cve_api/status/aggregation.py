"""Deterministic worst-state aggregation, bounded hysteresis and measured coverage."""

from datetime import datetime, timedelta
from typing import Any, cast

from cve_api.status.models import State

RANK = {"healthy": 0, "starting": 1, "degraded": 2, "unknown": 3, "unavailable": 4}


def worst(values: list[str]) -> State:
    return cast(State, max(values, key=lambda x: RANK[x])) if values else "unknown"


def fresh(state: str, observed_at: datetime | None, now: datetime, ttl: int) -> str:
    return (
        state
        if observed_at and timedelta(0) <= now - observed_at <= timedelta(seconds=ttl)
        else "unknown"
    )


def transition(previous: dict[str, Any] | None, raw: State) -> tuple[State, int, int]:
    failures = (
        (int(previous["failures"]) if previous else 0) + 1
        if raw in {"degraded", "unavailable"}
        else 0
    )
    successes = (int(previous["successes"]) if previous else 0) + 1 if raw == "healthy" else 0
    # Confirmed critical failures and unknown are visible immediately. Two successes to recover.
    effective: State = raw
    if raw == "healthy" and previous and previous["state"] != "healthy" and successes < 2:
        effective = "degraded"
    return effective, failures, successes


def availability(
    samples: list[dict[str, Any]], start: datetime, end: datetime, ttl: int
) -> dict[str, float | None]:
    if end <= start:
        raise ValueError("Finite time window required")
    intervals: list[tuple[datetime, datetime, str]] = []
    ordered = sorted(samples, key=lambda x: x["checked_at"])
    for index, sample in enumerate(ordered):
        a = max(start, sample["checked_at"])
        b = min(
            end,
            sample["checked_at"] + timedelta(seconds=ttl),
            ordered[index + 1]["checked_at"] if index + 1 < len(ordered) else end,
        )
        if b > a:
            intervals.append((a, b, sample["result"]))
    total = (end - start).total_seconds()
    known = sum(
        (b - a).total_seconds() for a, b, s in intervals if s not in {"unknown", "starting"}
    )
    healthy = sum((b - a).total_seconds() for a, b, s in intervals if s == "healthy")
    return {
        "window_seconds": total,
        "known_seconds": known,
        "unknown_seconds": total - known,
        "healthy_seconds": healthy,
        "coverage_percent": 100 * known / total,
        "available_percent": 100 * healthy / known if known else None,
    }


def platform(services: list[dict[str, Any]]) -> State:
    return worst(
        [
            "degraded"
            if not service.get("critical", True) and service["state"] == "unavailable"
            else service["state"]
            for service in services
        ]
    )
