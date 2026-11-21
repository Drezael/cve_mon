"""Reviewed forward-only migration plans; existing Alembic SQL advisory lock is retained."""

import hashlib
from pathlib import Path
from typing import Any

from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory

from scripts.deployment.contracts import read


def validate_plan(root: Path, path: Path, current: str, target: str) -> dict[str, Any]:
    plan = read(path)
    if set(plan) != {"schema_version", "current", "target", "strategy", "revision_sha256"}:
        raise ValueError("Invalid reviewed migration plan fields")
    if plan["schema_version"] != 1 or plan["current"] != current or plan["target"] != target:
        raise ValueError("Migration plan does not match database and release")
    if plan["strategy"] not in {"expand", "restore_required"}:
        raise ValueError("Reviewed migration/rollback classification required")
    directory = ScriptDirectory.from_config(AlembicConfig(str(root / "database/alembic.ini")))
    if directory.get_heads() != [target]:
        raise ValueError("Single target head required")
    try:
        revisions = list(directory.iterate_revisions(target, current))
    except Exception:
        raise ValueError("Unknown, branched or downgrade migration rejected") from None
    if not revisions:
        raise ValueError("Nonempty forward migration plan required")
    hashes = {
        revision.revision: hashlib.sha256(Path(revision.path).read_bytes()).hexdigest()
        for revision in revisions
    }
    if hashes != plan["revision_sha256"]:
        raise ValueError("Migration code differs from reviewed plan")
    return plan
