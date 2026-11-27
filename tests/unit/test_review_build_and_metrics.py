"""Stale build rejection, coverage floors, lock statistics and forward-only migration policy."""

import json
from pathlib import Path

import pytest

from scripts.dashboard.provenance import inputs, record, verify
from scripts.testing.coverage_gate import check
from scripts.testing.lock_metrics import summarize


def test_unsupported_build_host_fails_before_downloading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.dashboard.manage import node

    monkeypatch.setattr("scripts.dashboard.manage.platform.system", lambda: "Darwin")
    with pytest.raises(ValueError, match="Linux x86_64"):
        node(tmp_path)


def test_frontend_provenance_rejects_old_build_and_modified_assets(tmp_path: Path) -> None:
    dashboard = tmp_path / "services/dashboard"
    (dashboard / "src").mkdir(parents=True)
    (dashboard / "dist").mkdir()
    source = dashboard / "src/App.tsx"
    source.write_text("export const app = 1;")
    index = dashboard / "dist/index.html"
    index.write_text("<html>first build</html>")
    (dashboard / "toolchain.toml").write_text('version = "pinned"')
    record(tmp_path, inputs(tmp_path))
    verify(tmp_path)
    index.write_text("<html>substituted</html>")
    with pytest.raises(ValueError, match="stale"):
        verify(tmp_path)
    record(tmp_path, inputs(tmp_path))
    source.write_text("export const app = 2;")
    with pytest.raises(ValueError, match="stale"):
        verify(tmp_path)


def test_build_refuses_sources_changed_during_build(tmp_path: Path) -> None:
    dashboard = tmp_path / "services/dashboard"
    (dashboard / "src").mkdir(parents=True)
    before = inputs(tmp_path)
    (dashboard / "src/changed.ts").write_text("changed")
    with pytest.raises(ValueError, match="during build"):
        record(tmp_path, before)


def test_coverage_gate_rejects_missing_scope_and_regression() -> None:
    policy = {"scopes": {"auth": {"paths": ["auth/"], "minimum_lines": 50, "minimum_branches": 50}}}
    with pytest.raises(ValueError, match="Missing"):
        check({"files": {}}, policy)
    report = {
        "files": {
            "auth/service.py": {
                "summary": {
                    "num_statements": 10,
                    "covered_lines": 9,
                    "num_branches": 10,
                    "covered_branches": 8,
                }
            }
        }
    }
    assert check(report, policy)["auth"] == {"lines": 90, "branches": 80}
    report["files"]["auth/service.py"]["summary"]["covered_branches"] = 1
    with pytest.raises(ValueError, match="regression"):
        check(report, policy)


def test_lock_metrics_report_no_measurement_as_null() -> None:
    assert summarize([])["read_wait_seconds"]["p95"] is None
    values = [
        {"event": "security_lock_acquired", "mutation": False, "wait_seconds": i / 100}
        for i in range(1, 101)
    ]
    result = summarize(values)
    assert result["read_wait_seconds"]["p95"] == 0.95
    assert result["read_wait_seconds"]["p99"] == 0.99
    assert result["mutation_wait_seconds"]["samples"] == 0
    assert "0.95" in json.dumps(result)
