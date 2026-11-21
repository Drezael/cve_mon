"""Secret-Prüfung muss bei neuen und bereits versionierten Secrets fehlschlagen."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.security
@pytest.mark.parametrize("tracked", [False, True])
def test_secret_causes_failure_without_baseline_changes(
    repository_root: Path,
    git_repository: Path,
    tracked: bool,
) -> None:
    baseline = git_repository / "configuration/quality/secrets.baseline"
    baseline.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(repository_root / "configuration/quality/secrets.baseline", baseline)
    before = baseline.read_bytes()
    candidate = git_repository / "configuration.txt"
    # Synthetischer AWS-Identifier, kein echter Zugang; absichtlich erst zur Laufzeit erzeugt.
    candidate.write_text('aws_access_key_id = "' + "AKIA" + "Q7R8S9T0U1V2W3X4" + '"\n')
    if tracked:
        subprocess.run(["git", "add", candidate.name], cwd=git_repository, check=True)
        (git_repository / ".gitignore").write_text(candidate.name + "\n")
    command = [
        sys.executable,
        str(repository_root / "scripts/scan_secrets.py"),
        "--root",
        str(git_repository),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 1, result.stdout + result.stderr
    assert baseline.read_bytes() == before
    candidate.write_text("APP_ENV=development\n")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert baseline.read_bytes() == before


def test_unreviewed_baseline_is_rejected(repository_root: Path, git_repository: Path) -> None:
    baseline = json.loads((repository_root / "configuration/quality/secrets.baseline").read_text())
    baseline["results"] = {"somefile": [{"is_verified": True}]}
    (git_repository / "configuration/quality").mkdir(parents=True, exist_ok=True)
    (git_repository / "configuration/quality/secrets.baseline").write_text(json.dumps(baseline))
    result = subprocess.run(
        [
            sys.executable,
            str(repository_root / "scripts/scan_secrets.py"),
            "--root",
            str(git_repository),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "Baseline" in result.stderr


def test_baseline_metadata_updates_never_change_original(
    repository_root: Path,
    git_repository: Path,
) -> None:
    candidate = git_repository / "configuration.txt"
    candidate.write_text('aws_access_key_id = "' + "AKIA" + "Q7R8S9T0U1V2W3X4" + '"\n')
    result = subprocess.run(
        [
            str(Path(sys.executable).parent / "detect-secrets"),
            "scan",
            "--no-verify",
            "--all-files",
            candidate.name,
        ],
        cwd=git_repository,
        capture_output=True,
        text=True,
        check=True,
    )
    baseline = json.loads(result.stdout)
    assert baseline["results"]
    # Ausschließlich synthetische, bekannte Testdaten dieses temporären Repositorys.
    for findings in baseline["results"].values():
        for finding in findings:
            finding["is_verified"] = False
    baseline_path = git_repository / "configuration/quality/secrets.baseline"
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(baseline))
    before = baseline_path.read_bytes()
    candidate.write_text("\n" + candidate.read_text())
    result = subprocess.run(
        [
            sys.executable,
            str(repository_root / "scripts/scan_secrets.py"),
            "--root",
            str(git_repository),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert baseline_path.read_bytes() == before


def test_public_artifact_checksum_does_not_hide_adjacent_secret(
    repository_root: Path, git_repository: Path
) -> None:
    baseline = git_repository / "configuration/quality/secrets.baseline"
    baseline.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(repository_root / "configuration/quality/secrets.baseline", baseline)
    before = baseline.read_bytes()
    candidate = git_repository / "artifacts.lock.json"
    checksum = "a3f918bc72d04e65" * 4  # pragma: allowlist secret
    candidate.write_text(json.dumps({"sha256": checksum}, indent=2))
    command = [
        sys.executable,
        str(repository_root / "scripts/scan_secrets.py"),
        "--root",
        str(git_repository),
    ]
    assert subprocess.run(command, capture_output=True, check=False).returncode == 0
    candidate.write_text(
        json.dumps({"sha256": checksum, "aws_access_key_id": "AKIA" + "Q7R8S9T0U1V2W3X4"}, indent=2)
    )
    assert subprocess.run(command, capture_output=True, check=False).returncode == 1
    assert baseline.read_bytes() == before
