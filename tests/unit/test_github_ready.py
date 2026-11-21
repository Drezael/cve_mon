"""Publication checks reject private tracked files and accidental root clutter."""

import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.deployment.acceptance import task_inventory
from scripts.github_ready import publication_issues
from scripts.repository_files import repository_files
from scripts.validate_contracts import validate_contracts
from scripts.validate_repository import validate_structure


def prepare(root: Path) -> None:
    for name in ("README.md", "LICENSE", ".github/SECURITY.md", ".github/CONTRIBUTING.md"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Fixture\n")
    (root / ".gitignore").write_text(
        ".env\n.runtime/\n/docs/history/plans/\n/docs/development/phase-*-plan.md\n"
    )


def test_ignored_local_configuration_and_backups_are_excluded(git_repository: Path) -> None:
    prepare(git_repository)
    (git_repository / ".env").write_text("LOCAL_FIXTURE=1\n")
    data = git_repository / ".runtime" / "backup.key"
    data.parent.mkdir()
    data.write_text("fixture-only")
    assert publication_issues(git_repository) == []


def test_ignored_but_tracked_private_configuration_is_rejected(git_repository: Path) -> None:
    prepare(git_repository)
    (git_repository / ".env").write_text("LOCAL_FIXTURE=1\n")
    subprocess.run(["git", "add", "-f", ".env"], cwd=git_repository, check=True)
    assert any("Private Datei" in error for error in publication_issues(git_repository))


def test_example_inventories_belong_below_examples(git_repository: Path) -> None:
    prepare(git_repository)
    sample = git_repository / "sample.json"
    sample.write_text("{}\n")
    assert publication_issues(git_repository) == ["Unerwartete Datei im Repo-Root: sample.json"]
    target = git_repository / "examples/inventories/sample.json"
    target.parent.mkdir(parents=True)
    sample.rename(target)
    assert publication_issues(git_repository) == []


def test_github_size_limit_is_checked_without_reading_the_file(git_repository: Path) -> None:
    prepare(git_repository)
    target = git_repository / "examples/oversized.bin"
    target.parent.mkdir()
    with target.open("wb") as stream:
        stream.truncate(100 * 1024 * 1024)
    assert any("Dateilimit" in error for error in publication_issues(git_repository))


@pytest.mark.parametrize(
    "relative", ["docs/history/plans/phase_00.md", "docs/development/phase-24-plan.md"]
)
def test_private_plans_are_excluded_and_forced_additions_are_rejected(
    git_repository: Path,
    relative: str,
) -> None:
    prepare(git_repository)
    path = git_repository / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Private local development plan\n")
    assert publication_issues(git_repository) == []
    subprocess.run(["git", "add", "-f", relative], cwd=git_repository, check=True)
    assert any("Privater Entwicklungsplan" in item for item in publication_issues(git_repository))


def test_public_checkout_works_without_local_development_plans(
    repository_root: Path,
    git_repository: Path,
) -> None:
    for source in repository_files(repository_root):
        target = git_repository / source.relative_to(repository_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    assert not (git_repository / "docs/history/plans").exists()
    assert not list((git_repository / "docs/development").glob("phase-*-plan.md"))
    assert validate_structure(git_repository) == []
    assert validate_contracts(git_repository) == []
    assert len(task_inventory(git_repository)) == 45
    assert publication_issues(git_repository) == []
