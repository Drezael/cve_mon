"""Narrow PostgreSQL dump/reparse equivalence for unconstrained varchar literal arrays.

PostgreSQL can distribute an outer varchar[] -> text[] coercion over literal elements
when reparsing pg_dump DDL. Only these two representations are normalized. Owners,
ACLs, operators, literals, indexes and all other catalog fields remain compared.
"""

import copy
import re
from typing import Any

LITERAL = r"'(?:[^']|'')*'"
RAW = re.compile(r"\s*(" + LITERAL + r")::character varying\s*")
ELEMENT = re.compile(r"\s*\((" + LITERAL + r")::character varying\)::text\s*")
ARRAY = re.compile(
    r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|"
    r"\(ARRAY\[([^\[\]]*)\]\)::text\[\]|ARRAY\[([^\[\]]*)\]"
)


def text_arrays(definition: str) -> str:
    def replace(match: re.Match[str]) -> str:
        body = match.group(1) if match.group(1) is not None else match.group(2)
        if body is None:
            return match.group(0)
        pattern = RAW if match.group(1) is not None else ELEMENT
        parts = []
        position = 0
        while position < len(body):
            found = pattern.match(body, position)
            if not found:
                return match.group(0)
            parts.append(found.group(1) + "::text")
            position = found.end()
            if position == len(body):
                break
            if body[position] != ",":
                return match.group(0)
            position += 1
            if position == len(body):
                return match.group(0)
        return "ARRAY[" + ", ".join(parts) + "]" if parts else match.group(0)

    return ARRAY.sub(replace, definition)


def equivalent(database: str, actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    if database != "n8n":
        return actual == expected

    def normalized(value: dict[str, Any]) -> dict[str, Any]:
        result = copy.deepcopy(value)
        for section, field in [("constraints", "definition"), ("indexes", "indexdef")]:
            for row in result.get(section, []):
                if row.get("nspname", row.get("schemaname")) == "public":
                    row[field] = text_arrays(row[field])
        return result

    return normalized(actual) == normalized(expected)
