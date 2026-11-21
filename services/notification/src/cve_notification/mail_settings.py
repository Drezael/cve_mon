"""Personal destinations and non-secret routing metadata; transport secrets remain in Postfix."""

import json
from pathlib import Path
from typing import Any


def destinations(configuration: dict[str, Any] | None, email: str) -> list[str]:
    return configuration["recipients"] if configuration else [email]


def route(
    directory: Path, user: str, configuration: dict[str, Any] | None
) -> dict[str, str] | None:
    path = directory / "smtp-delivery.json"
    if not path.exists():
        return None
    profiles: dict[str, dict[str, str]] = json.loads(path.read_text())
    owner = user if configuration and configuration["mode"] == "custom" else "system"
    return profiles.get(owner)
