"""Reviewed forward plans bind exact migration code, current schema and rollback class."""

import hashlib
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

from scripts.deployment.contracts import ROOT, atomic
from scripts.deployment.migrations import validate_plan


@pytest.mark.parametrize("mutation", [None, "hash", "current", "strategy", "target", "extra"])
def test_forward_plan_rejects_unreviewed_changes(tmp_path: Path, mutation: str | None) -> None:
    scripts = ScriptDirectory.from_config(Config(str(ROOT / "database/alembic.ini")))
    target = scripts.get_current_head()
    assert target is not None
    revision = scripts.get_revision(target)
    assert revision is not None and isinstance(revision.down_revision, str)
    current = revision.down_revision
    plan = {
        "schema_version": 1,
        "current": current,
        "target": target,
        "strategy": "expand",
        "revision_sha256": {target: hashlib.sha256(Path(revision.path).read_bytes()).hexdigest()},
    }
    path = tmp_path / "plan.json"
    if mutation == "hash":
        plan["revision_sha256"] = {target: "0" * 64}
    elif mutation:
        plan[mutation] = "unreviewed"
    atomic(path, plan)
    if mutation:
        with pytest.raises(ValueError):
            validate_plan(ROOT, path, current, target)
    else:
        assert validate_plan(ROOT, path, current, target) == plan


def test_schema_downgrade_is_not_a_forward_plan(tmp_path: Path) -> None:
    path = tmp_path / "plan.json"
    atomic(
        path,
        {
            "schema_version": 1,
            "current": "unknown",
            "target": "unknown",
            "strategy": "restore_required",
            "revision_sha256": {},
        },
    )
    with pytest.raises(ValueError):
        validate_plan(ROOT, path, "unknown", "unknown")
