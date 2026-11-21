"""Prüfe Entwicklungsregeln sowie positive und negative Konfigurationsfälle."""

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

from scripts.repository_files import repository_files
from scripts.validate_repository import validate_configuration, validate_configurations


def test_python_and_tool_settings(repository_root: Path) -> None:
    assert sys.version_info[:2] == (3, 12)
    config = tomllib.loads((repository_root / "pyproject.toml").read_text())
    assert "project" not in config
    assert config["tool"]["ruff"]["target-version"] == "py312"
    assert config["tool"]["ruff"]["line-length"] == 100
    assert config["tool"]["mypy"]["strict"] is True
    assert config["tool"]["mypy"]["python_version"] == "3.12"
    assert config["tool"]["pytest"]["ini_options"]["testpaths"] == ["tests"]


def test_environment_template_is_documented_and_nonsecret(repository_root: Path) -> None:
    settings = dict(
        line.split("=", 1)
        for line in (repository_root / ".env.example").read_text().splitlines()
        if line and not line.startswith("#")
    )
    assert {key: settings[key] for key in ("APP_ENV", "COMPOSE_PROJECT_NAME")} == {
        "APP_ENV": "production",
        "COMPOSE_PROJECT_NAME": "cve-monitoring-prod",
    }
    documentation = (repository_root / "docs/development/developer-setup.md").read_text() + (
        repository_root / "docs/deployment/environments.md"
    ).read_text()
    assert all(name in documentation for name in settings)


@pytest.mark.parametrize(
    ("name", "content", "valid"),
    [
        ("valid.yaml", "setting: true\n", True),
        ("multi.yml", "---\na: 1\n---\nb: 2\n", True),
        ("broken.yaml", "setting: [\n", False),
        ("unsafe.yml", "!!python/object/apply:os.system ['false']", False),
        ("valid.json", '{"setting": true}', True),
        ("broken.json", '{"setting": }', False),
        ("nan.json", '{"value": NaN}', False),
        ("valid.schema.json", '{"type": "object"}', True),
        ("invalid.schema.json", '{"type": "unknown"}', False),
        ("schema.json", '{"$schema": "https://invalid.test/schema"}', False),
        ("boolean.schema.json", "true", True),
        ("number.schema.json", "12", False),
        (
            "document.json",
            '{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": 17}',
            False,
        ),
    ],
)
def test_configuration_validation(tmp_path: Path, name: str, content: str, valid: bool) -> None:
    path = tmp_path / name
    path.write_text(content)
    errors = validate_configuration(path)
    assert (not errors) == valid
    if errors:
        assert str(path) in errors[0]


def test_new_yaml_and_json_files_are_automatically_checked(
    repository_root: Path,
    git_repository: Path,
) -> None:
    (git_repository / "configuration/quality").mkdir(parents=True, exist_ok=True)
    (git_repository / "configuration/quality/yamllint.yml").write_text(
        (repository_root / "configuration/quality/yamllint.yml").read_text()
    )
    (git_repository / "new.json").write_text("{broken}")
    (git_repository / "new.yml").write_text("duplicate: 1\nduplicate: 2\n")
    errors = validate_configurations(git_repository)
    assert any("new.json" in error for error in errors)
    assert any("duplication" in error for error in errors)
    (git_repository / "new.json").write_text("{}\n")
    (git_repository / "new.yml").write_text("setting: true\n")
    assert validate_configurations(git_repository) == []


def test_git_file_selection_covers_tracked_and_new_files(git_repository: Path) -> None:
    (git_repository / "tracked.env").write_text("local setting")
    subprocess.run(["git", "add", "tracked.env"], cwd=git_repository, check=True)
    (git_repository / ".gitignore").write_text("*.env\n")
    (git_repository / "ignored.env").write_text("local setting")
    (git_repository / "new file.json").write_text("{}")
    names = {path.name for path in repository_files(git_repository)}
    assert names == {".gitignore", "tracked.env", "new file.json"}


def test_symlinks_are_rejected(git_repository: Path, tmp_path: Path) -> None:
    (git_repository / "link").symlink_to(tmp_path / "outside")
    with pytest.raises(ValueError, match="Symlink"):
        repository_files(git_repository)


@pytest.mark.parametrize(
    "name",
    [
        ".env",
        ".env.local",
        "private.key",
        "certificate.pem",
        "bundle.p12",
        "bundle.pfx",
        ".venv/example",
        "__pycache__/example.pyc",
        ".pytest_cache/file",
        ".mypy_cache/file",
        ".ruff_cache/file",
        "runtime/file",
        "data/file",
        "volumes/file",
        "secrets/file",
        "inventory_uploads/file",
        "database.dump",
        "backup.sql.gz",
        ".vscode/settings.json",
    ],
)
def test_local_artifacts_are_ignored(repository_root: Path, name: str) -> None:
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", name],
        cwd=repository_root,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0


def test_templates_remain_versionable(repository_root: Path) -> None:
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", ".env.example", "README.md", "pyproject.toml"],
        cwd=repository_root,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1


def test_lock_has_only_exact_hashed_requirements(repository_root: Path) -> None:
    text = (repository_root / "requirements/dev.txt").read_text()
    logical = text.replace("\\\n", " ")
    requirements = [
        line for line in logical.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    assert requirements
    for line in requirements:
        assert re.match(r"^[a-zA-Z0-9_.-]+==[^\s]+\s+--hash=sha256:[0-9a-f]{64}", line)
    assert "--index-url" not in text


def test_ci_calls_local_checks_and_pins_actions(repository_root: Path) -> None:
    workflow = yaml.safe_load((repository_root / ".github/workflows/quality.yml").read_text())
    assert workflow["permissions"] == {"contents": "read"}
    steps = workflow["jobs"]["quality"]["steps"]
    assert {step.get("run") for step in steps} >= {"make setup", "make check"}
    for step in steps:
        if "uses" in step:
            assert re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", step["uses"])


def test_baseline_has_no_accepted_findings(repository_root: Path) -> None:
    baseline = json.loads((repository_root / "configuration/quality/secrets.baseline").read_text())
    assert baseline["results"] == {}


@pytest.mark.parametrize("processes", ["0", "1", "2", "3", "unbounded"])
def test_matcher_process_budget_cannot_be_overridden(processes: str) -> None:
    from scripts.infrastructure.manage import load_config

    with pytest.raises(ValueError, match="Nur externe"):
        load_config(overrides={"CVE_MATCHER_PROCESSES": processes})
