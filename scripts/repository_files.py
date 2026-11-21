"""Gemeinsame Dateiauswahl für lokale Prüfungen und CI."""

import subprocess
from pathlib import Path


def repository_files(root: Path) -> list[Path]:
    """Erfasse versionierte und neue, nicht ignorierte Dateien via Git.

    Bereits versionierte Dateien bleiben auch bei nachträglichen Ignore-Regeln sichtbar.
    Externe Symlinks werden nicht verfolgt.
    """
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    files: list[Path] = []
    for name in sorted(set(result.stdout.decode("utf-8").split("\0")) - {""}):
        path = root / name
        if path.is_symlink():
            raise ValueError(f"Symlink manuell prüfen: {name}")
        if path.is_file():
            files.append(path)
    return files
