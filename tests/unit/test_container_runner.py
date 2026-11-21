"""The bridge uses this repository's fixed collector and internal upload client."""

from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from scripts.ansible import manage, submit
from scripts.container_inventory import runner


def test_local_collection_is_submitted_without_an_external_launcher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = str(uuid4())
    submitted = str(uuid4())
    connection = tmp_path / "target.json"
    document = {"host": {"monitoring_id": identity}}
    calls: list[Any] = []

    def collect(path: Path) -> dict[str, Any]:
        assert path == connection
        calls.append("collect")
        return document

    def upload(config: dict[str, Any], raw: bytes) -> dict[str, Any]:
        import json

        assert json.loads(raw) == document
        calls.append("submit")
        return {"submission_id": submitted}

    monkeypatch.setattr(manage, "collect", collect)
    monkeypatch.setattr(submit, "submit", upload)
    assert (
        runner.execute({"targets": {"web": {"connection_file": str(connection)}}}, "web")
        == submitted
    )
    assert calls == ["collect", "submit"]


def test_unknown_alias_cannot_start_collection() -> None:
    with pytest.raises(ValueError, match="Unregistered"):
        runner.execute({"targets": {}}, "unknown")
