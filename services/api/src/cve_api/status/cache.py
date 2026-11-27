"""Bounded process-local live status; reads never refresh or extend measurement lifetimes."""

from collections import defaultdict, deque
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import uuid4

from cve_api.status.aggregation import fresh, transition, worst
from cve_api.status.catalog import CATALOG, PIPELINES, topological
from cve_api.status.models import Observation, State


class StatusCache:
    def __init__(self, stale_seconds: int = 180) -> None:
        self.stale_seconds = stale_seconds
        self.created_at = datetime.now(UTC)
        self.control_checked_at: datetime | None = None
        self.observations: dict[tuple[str, str], Observation] = {}
        self.current: dict[str, dict[str, Any]] = {}
        self.history: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=512))
        self.samples: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=2000)
        )
        self.control: dict[str, Any] | None = None

    def publish(self, observations: list[Observation]) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        changed_services: set[str] = set()
        for item in observations:
            if (
                item.service_id not in CATALOG
                or item.check_id
                not in {"liveness", "readiness", "functional", "backlog", "freshness"}
                or not 0 <= (now - item.checked_at).total_seconds() <= self.stale_seconds
            ):
                continue
            observation_key = (item.service_id, item.check_id)
            old = self.observations.get(observation_key)
            if old and old.checked_at >= item.checked_at:
                continue
            self.observations[observation_key] = item.model_copy(deep=True)
            self.samples[observation_key].append(item.model_dump())
            changed_services.add(item.service_id)
        changed: list[dict[str, Any]] = []
        for key in topological():
            if key not in changed_services:
                continue
            items = [v for (service, _), v in self.observations.items() if service == key]
            core = [v for v in items if v.check_id in {"liveness", "readiness"}]
            scored = [
                (v, cast(State, fresh(v.result, v.checked_at, now, self.stale_seconds)))
                for v in items
            ]
            # Missing diagnostics must not erase a confirmed, fresh protocol response.
            if core:
                scored = [(v, state) for v, state in scored if state != "unknown" or v in core]
            raw = worst([state for _, state in scored])
            reason = next((v.reason_code for v, state in scored if state == raw), "NO_OBSERVATION")
            at = min(v.checked_at for v in core) if core else max(v.checked_at for v in items)
            previous = self.current.get(key)
            state, failures, successes = transition(previous, raw)
            row: dict[str, Any] = {
                "id": key,
                "kind": "service",
                "name": CATALOG[key].name,
                "dependencies": list(CATALOG[key].dependencies),
                "critical": CATALOG[key].critical,
                "raw_state": raw,
                "state": state,
                "reason_code": reason,
                "observed_at": at,
                "last_success_at": at
                if state == "healthy"
                else (previous or {}).get("last_success_at"),
                "version": (previous or {}).get("version", 0) + 1,
                "changes": (previous or {}).get("changes", 0)
                + int(not previous or previous["state"] != state),
                "failures": failures,
                "successes": successes,
            }
            self.current[key] = row
            if not previous or previous["state"] != state:
                event = {
                    "id": uuid4(),
                    "previous_state": (previous or {}).get("state"),
                    "state": state,
                    "raw_state": raw,
                    "reason_code": reason,
                    "observed_at": at,
                    "decided_at": now,
                    "run_id": uuid4(),
                    "version": row["version"],
                }
                self.history[key].append(event)
                changed.append(deepcopy(row))
        return changed

    def rows(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for key, service in CATALOG.items():
            result.append(
                deepcopy(
                    self.current.get(key)
                    or {
                        "id": key,
                        "kind": "service",
                        "name": service.name,
                        "dependencies": list(service.dependencies),
                        "critical": service.critical,
                        "raw_state": "starting",
                        "state": "starting",
                        "reason_code": "CACHE_WARMING",
                        "observed_at": self.created_at,
                        "last_success_at": None,
                        "version": 0,
                        "changes": 0,
                    }
                )
            )
        for key, (name, members) in PIPELINES.items():
            result.append(
                {
                    "id": "pipeline-" + key,
                    "kind": "pipeline",
                    "name": name,
                    "dependencies": list(members),
                    "critical": True,
                    "raw_state": "starting",
                    "state": "starting",
                    "reason_code": "PIPELINE_MEMBERS",
                    "observed_at": max(
                        (
                            r["observed_at"]
                            for r in result
                            if r["id"] in members and r["observed_at"]
                        ),
                        default=None,
                    ),
                    "last_success_at": None,
                    "version": 0,
                    "changes": 0,
                }
            )
        return result

    def checks(self, service: str) -> list[dict[str, Any]]:
        return [
            v.model_dump() | {"definition_version": 1, "stale_seconds": self.stale_seconds}
            for (key, _), v in self.observations.items()
            if key == service
        ]

    def recent_changes(self, service: str) -> int:
        start = datetime.now(UTC) - timedelta(minutes=15)
        return sum(v["observed_at"] > start for v in self.history.get(service, []))

    def set_control(self, value: dict[str, Any]) -> None:
        self.control = deepcopy(value)
        self.control_checked_at = datetime.now(UTC)

    def read_control(self) -> dict[str, Any]:
        if (
            self.control is not None
            and self.control_checked_at
            and (datetime.now(UTC) - self.control_checked_at).total_seconds() <= self.stale_seconds
        ):
            return deepcopy(self.control) | {
                "sample_stale": False,
                "sample_checked_at": self.control_checked_at,
            }
        return (
            deepcopy(self.control)
            if self.control is not None
            else {
                "enabled": None,
                "heartbeat_at": None,
                "pending": None,
                "processing": None,
                "paused": None,
                "failed": None,
                "oldest_seconds": None,
                "expired_leases": None,
                "capped": False,
            }
        ) | {"sample_stale": True, "sample_checked_at": self.control_checked_at}
