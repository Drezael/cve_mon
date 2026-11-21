"""Strong opaque preconditions; no unconditional write fallback."""

import re

from cve_api.authorization.errors import Denied


def expected(value: str | None) -> int:
    if value is None:
        raise Denied(428, "precondition_required")
    if not re.fullmatch(r'"[1-9][0-9]{0,17}"', value):
        raise Denied(400, "invalid_etag")
    return int(value[1:-1])


def check(actual: int, match: str | None) -> None:
    if expected(match) != actual:
        raise Denied(412, "stale_version")


def etag(version: int) -> str:
    return '"' + str(version) + '"'
