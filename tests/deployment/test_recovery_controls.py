"""Runtime access modes must survive encryption without exposing plaintext backups."""

import stat
from pathlib import Path
from typing import Any

import pytest

from scripts.deployment.recovery import capture_configuration, restore_configuration_modes


def test_public_runtime_directory_and_private_key_modes_survive(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir(mode=0o755)
    public = source / "envoy.yaml"
    public.write_text("node: {}")
    public.chmod(0o644)
    private = source / "private.key"
    private.write_text("synthetic fixture")
    private.chmod(0o600)
    plain = tmp_path / "plain"
    plain.mkdir(mode=0o700)
    modes: dict[str, dict[str, Any]] = {}
    destination = plain / "configuration/envoy"
    capture_configuration(source, destination, plain, modes)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert stat.S_IMODE((destination / "envoy.yaml").stat().st_mode) == 0o600
    restore_configuration_modes(plain, modes)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o755
    assert stat.S_IMODE((destination / "envoy.yaml").stat().st_mode) == 0o644
    assert stat.S_IMODE((destination / "private.key").stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "name,mode",
    [
        ("../outside", 0o644),
        ("/outside", 0o644),
        ("unreviewed/file", 0o644),
        ("configuration/unsafe", 0o777),
        ("configuration/unsafe", 0o4755),
    ],
)
def test_permission_metadata_cannot_escape_or_grant_unsafe_access(
    tmp_path: Path,
    name: str,
    mode: int,
) -> None:
    with pytest.raises(ValueError):
        restore_configuration_modes(tmp_path, {name: {"mode": mode, "directory": True}})
    assert not list(tmp_path.iterdir())
