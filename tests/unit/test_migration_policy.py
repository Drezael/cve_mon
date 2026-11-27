"""Released migration bytes are immutable; new migrations declare complete SQL definitions."""

import hashlib
import json
from pathlib import Path


def test_released_migrations_match_reviewed_baseline() -> None:
    root = Path(__file__).resolve().parents[2]
    baseline = json.loads((root / "configuration/quality/migration-baseline.json").read_text())
    for entry in baseline["files"]:
        assert hashlib.sha256((root / entry["file"]).read_bytes()).hexdigest() == entry["sha256"]
    released = {entry["file"] for entry in baseline["files"]}
    for path in (root / "database/migrations/versions").glob("*.py"):
        if str(path.relative_to(root)) not in released:
            assert "pg_get_functiondef" not in path.read_text(), (
                "New migrations must use complete target definitions, not formatted body patches"
            )
