"""Known sensitive fields/registered secrets and credential URLs are always masked."""

import re
from typing import Any

from pydantic import SecretStr

_VALUES: set[str] = set()
SENSITIVE = re.compile(
    r"password|secret|token|authorization|cookie|private.?key|body|credential", re.I
)


def register_secret(value: SecretStr) -> None:
    _VALUES.add(value.get_secret_value())


def redact(value: Any, key: str = "") -> Any:
    if SENSITIVE.search(key) or isinstance(value, SecretStr):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r"[a-z][a-z0-9+.-]*://[^\s/@]+:[^\s/@]+@", "[REDACTED-URL]@", value)
        value = re.sub(
            r"(?is)-----BEGIN .*?PRIVATE KEY-----.*?-----END .*?PRIVATE KEY-----",
            "[REDACTED]",
            value,
        )
        for secret in sorted(_VALUES, key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        return value
    return value if value is None or isinstance(value, (bool, int, float)) else "[REDACTED-OBJECT]"
