"""Immutable Docker Hub image identities shared by Compose validation and builders."""

import json
from pathlib import Path

REFERENCES: dict[str, str] = json.loads(
    (Path(__file__).resolve().parents[2] / "infrastructure/images.lock.json").read_text()
)
