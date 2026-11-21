"""OSV timeline and independent range limits, using declared ecosystem semantics."""

from functools import cmp_to_key
from typing import Any

from cve_matcher.versions import VersionError, compare, ecosystem_adapter


def osv_range(version: str, value: dict[str, Any], ecosystem: str) -> tuple[bool | None, str]:
    kind = value.get("type")
    if kind == "GIT":
        return None, "git_graph_unavailable"
    adapter = "semver" if kind == "SEMVER" else ecosystem_adapter(ecosystem)
    if kind not in {"SEMVER", "ECOSYSTEM"} or adapter is None:
        return None, "unsupported_comparator"
    events = value.get("events", [])
    if not isinstance(events, list) or not 1 <= len(events) <= 1024:
        return None, "invalid_range"
    timeline: list[tuple[str, str]] = []
    limits: list[str] = []
    try:
        compare(adapter, version, version)
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                return None, "invalid_range"
            op, boundary = next(iter(event.items()))
            if op not in {"introduced", "fixed", "last_affected", "limit"} or not isinstance(
                boundary, str
            ):
                return None, "invalid_range"
            if (boundary != "0" or op != "introduced") and not (op == "limit" and boundary == "*"):
                compare(adapter, boundary, boundary)
            if op == "limit":
                limits.append(boundary)
            else:
                timeline.append((op, boundary))
        operations = {op for op, _ in timeline}
        if "introduced" not in operations or {"fixed", "last_affected"} <= operations:
            return None, "invalid_range"
        if limits and not any(b == "*" or compare(adapter, version, b) < 0 for b in limits):
            return False, "outside_osv_limit"

        def order(a: tuple[str, str], b: tuple[str, str]) -> int:
            if a[0] == "introduced" and a[1] == "0":
                return 0 if b == (a[0], a[1]) else -1
            if b[0] == "introduced" and b[1] == "0":
                return 1
            return compare(adapter, a[1], b[1])

        timeline.sort(key=cmp_to_key(order))
        for a, b in zip(timeline, timeline[1:], strict=False):
            if order(a, b) == 0 and a[0] != b[0]:
                return None, "invalid_range"
        affected = False
        for op, boundary in timeline:
            if op == "introduced" and (boundary == "0" or compare(adapter, version, boundary) >= 0):
                affected = True
            elif (
                op == "fixed"
                and compare(adapter, version, boundary) >= 0
                or op == "last_affected"
                and compare(adapter, version, boundary) > 0
            ):
                affected = False
        return affected, "osv_interval" if affected else "outside_osv_intervals"
    except VersionError as error:
        return None, str(error)


def osv(version: str | None, affected: dict[str, Any]) -> tuple[bool | None, str, str | None]:
    if not version:
        return None, "missing_version", None
    ecosystem = affected.get("package", {}).get("ecosystem", "")
    adapter = ecosystem_adapter(ecosystem)
    versions, ranges = affected.get("versions", []), affected.get("ranges", [])
    if not isinstance(versions, list) or not isinstance(ranges, list) or len(ranges) > 128:
        return None, "invalid_range", adapter
    if version in versions:
        return True, "osv_explicit_version", adapter
    results = [
        osv_range(version, r, ecosystem) if isinstance(r, dict) else (None, "invalid_range")
        for r in ranges
    ]
    if any(v is True for v, _ in results):
        return True, "osv_interval", adapter
    if any(v is None for v, _ in results):
        return None, next(reason for v, reason in results if v is None), adapter
    # Outside a declared limit is outside the source's evaluated scope, not a fix.
    if any(reason == "outside_osv_limit" for _, reason in results):
        return None, "outside_osv_limit", adapter
    if results or versions:
        return False, "outside_osv_intervals", adapter
    return None, "missing_range", adapter
