"""One deliberately ASCII mailbox contract for accounts, SMTP and notifications."""

import re

EMAIL = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,63}"
)


def normalize_address(value: str) -> str:
    value = value.strip()
    local, separator, domain = value.rpartition("@")
    normalized = local + separator + domain.lower()
    if (
        len(normalized) > 254
        or not EMAIL.fullmatch(normalized)
        or ".." in local
        or local.endswith(".")
        or any(
            not label or label.startswith("-") or label.endswith("-") or len(label) > 63
            for label in domain.split(".")
        )
    ):
        raise ValueError("A single ASCII email address is required")
    return normalized
