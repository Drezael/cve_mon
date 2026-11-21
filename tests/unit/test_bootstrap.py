"""Prüfe Setup-Schutzregeln ohne die reale Entwicklungsumgebung zu verändern."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("scenario", ["wrong-version", "invalid-venv", "pip-failure"])
def test_bootstrap_reports_failures(
    repository_root: Path,
    tmp_path: Path,
    scenario: str,
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copyfile(repository_root / "scripts/bootstrap_dev.sh", scripts / "bootstrap_dev.sh")
    shutil.copyfile(repository_root / "cve_mon", tmp_path / "cve_mon")
    (tmp_path / "cve_mon").chmod(0o755)
    interpreter = tmp_path / "python-test"
    interpreter.write_text(
        "#!/bin/sh\nexit " + ("1" if scenario == "wrong-version" else "0") + "\n"
    )
    interpreter.chmod(0o755)
    venv = tmp_path / ".venv"
    if scenario == "invalid-venv":
        venv.mkdir()
        (venv / "preserve-me").write_text("important")
    if scenario == "pip-failure":
        (venv / "bin").mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("test")
        fake_python = venv / "bin/python"
        fake_python.write_text('#!/bin/sh\nif [ "$1" = "-m" ]; then exit 23; fi\nexit 0\n')
        fake_python.chmod(0o755)
    result = subprocess.run(
        ["bash", str(scripts / "bootstrap_dev.sh")],
        env={**os.environ, "PYTHON": str(interpreter)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    if scenario == "wrong-version":
        assert "Python 3.12" in result.stderr
        assert not venv.exists()
    if scenario == "invalid-venv":
        assert "Vorhandene .venv" in result.stderr
        assert (venv / "preserve-me").read_text() == "important"
    if scenario == "pip-failure":
        assert result.returncode == 23
