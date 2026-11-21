"""Prüfe tatsächliche Struktur und Fehlererkennung ohne Projektdateien zu löschen."""

from pathlib import Path

from scripts.repository_files import repository_files
from scripts.validate_repository import REQUIRED_DIRS, REQUIRED_FILES, validate_structure


def test_repository_structure(repository_root: Path) -> None:
    assert validate_structure(repository_root) == []


def test_missing_files_and_directories_are_reported(tmp_path: Path) -> None:
    for name in REQUIRED_DIRS:
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    for name in REQUIRED_FILES:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    assert validate_structure(tmp_path) == []
    (tmp_path / "pyproject.toml").unlink()
    (tmp_path / "tests/end-to-end").rmdir()
    assert validate_structure(tmp_path) == [
        "Verzeichnis fehlt: tests/end-to-end",
        "Datei fehlt: pyproject.toml",
    ]


def test_no_premature_runtime_components(repository_root: Path) -> None:
    implemented = [
        p
        for p in repository_files(repository_root)
        if p.suffix == ".py" and p.is_relative_to(repository_root / "services")
    ]
    assert implemented
    assert all(
        (
            path.is_relative_to(repository_root / "services/api/src/cve_api")
            or path.is_relative_to(repository_root / "services/automation/src/cve_automation")
            or path.is_relative_to(
                repository_root / "services/event-dispatcher/src/cve_event_dispatcher"
            )
            or path.is_relative_to(repository_root / "services/inventory/src/cve_inventory")
            or path.is_relative_to(repository_root / "services/importer/src/cve_importer")
            or path.is_relative_to(repository_root / "services/enricher/src/cve_enricher")
            or path.is_relative_to(repository_root / "services/matcher/src/cve_matcher")
            or path.is_relative_to(repository_root / "services/findings/src/cve_findings")
            or path.is_relative_to(repository_root / "services/notification/src/cve_notification")
        )
        for path in implemented
    )
    # Only API, dispatcher, inventory and the Phase-15 source importer are implemented.
