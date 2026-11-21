"""Integrity failures must not publish an artifact or follow a supplied symlink."""

import hashlib
import io
from pathlib import Path

import pytest

from scripts.hardening.runtime_images import fetch

pytestmark = pytest.mark.security


def test_download_checksum_is_checked_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"public synthetic build artifact"
    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: io.BytesIO(payload))
    target = tmp_path / "artifact"
    with pytest.raises(ValueError):
        fetch("https://example.invalid/artifact", "invalid", target)
    assert not target.exists()
    checksum = hashlib.sha256(payload).hexdigest()
    fetch("https://example.invalid/artifact", checksum, target)
    assert target.read_bytes() == payload
    target.write_bytes(b"tampered")
    with pytest.raises(ValueError):
        fetch("https://example.invalid/artifact", checksum, target)


def test_artifact_symlink_cannot_write_outside_build_context(tmp_path: Path) -> None:
    outside = tmp_path / "must-not-be-created"
    target = tmp_path / "artifact"
    target.symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        fetch("https://example.invalid/artifact", "unused", target)
    assert not outside.exists()


@pytest.mark.parametrize("present", [True, False])
def test_vendor_runtime_only_pulls_original_images(
    present: bool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import subprocess

    from scripts.hardening import runtime_images

    calls: list[list[str]] = []

    def invoke(arguments: list[str], *, timeout: int = 600) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        if "inspect" in arguments and not present:
            raise subprocess.CalledProcessError(1, arguments)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr(runtime_images, "call", invoke)
    for runtime in runtime_images.IMAGES:
        runtime_images.build_at(tmp_path, runtime)
    assert all("build" not in arguments and "tag" not in arguments for arguments in calls)
    assert sum("pull" in arguments for arguments in calls) == (
        0 if present else len(runtime_images.IMAGES)
    )
    assert all("@sha256:" in arguments[-1] for arguments in calls)
