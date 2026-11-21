"""Gemeinsame Fixtures ohne Datenbank oder produktive Dienste."""

import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def repository_root() -> Path:
    """Liefere den tatsächlichen Projektpfad unabhängig vom Arbeitsverzeichnis."""
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def git_repository(tmp_path: Path) -> Path:
    """Isoliere destruktive Fehlerszenarien in einem temporären Git-Repository."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path
