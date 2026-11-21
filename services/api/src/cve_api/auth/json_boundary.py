"""Reject ambiguous/nonstandard JSON before model validation in bounded dashboard requests."""

import json
import math
from typing import Any


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("Ambiguous JSON object")
        result[key] = value
    return result


def finite(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Finite JSON numbers required")
    return result


def reject_constant(_value: str) -> Any:
    raise ValueError("Standard JSON required")


def validate(raw: bytes) -> None:
    decoded = raw.decode("utf-8", errors="strict")
    depth = 0
    quoted = False
    escaped = False
    for char in decoded:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 32:
                raise ValueError("Bounded JSON depth required")
        elif char in "]}":
            depth -= 1
    value = json.loads(
        decoded, object_pairs_hook=pairs, parse_float=finite, parse_constant=reject_constant
    )
    # PostgreSQL text/JSONB cannot represent NUL or unpaired surrogate code points.
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str) and (
            "\0" in item or any(0xD800 <= ord(c) <= 0xDFFF for c in item)
        ):
            raise ValueError("Representable Unicode required")
