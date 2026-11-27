"""Gemeinsame Fixtures ohne Datenbank oder produktive Dienste."""

import os
import subprocess
from pathlib import Path

import pytest

os.environ.setdefault(
    "CVE_ENV_FILE",
    str(Path(__file__).resolve().parents[1] / "configuration/examples/development.env"),
)

pytest_plugins = ["tests.network_pool"]


@pytest.fixture
def repository_root() -> Path:
    """Liefere den tatsächlichen Projektpfad unabhängig vom Arbeitsverzeichnis."""
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def git_repository(tmp_path: Path) -> Path:
    """Isoliere destruktive Fehlerszenarien in einem temporären Git-Repository."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path
