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


def test_managed_dashboard_pointer_is_materialized_without_a_restorable_link(
    tmp_path: Path,
) -> None:
    source = tmp_path / "nginx"
    release = source / "dashboard-releases/release-current"
    release.mkdir(parents=True, mode=0o755)
    release.chmod(0o755)
    (release / "index.html").write_text("reviewed dashboard")
    (source / "dashboard").symlink_to(
        "dashboard-releases/release-current", target_is_directory=True
    )
    plain = tmp_path / "plain"
    plain.mkdir(mode=0o700)
    destination = plain / "configuration/nginx"
    modes: dict[str, dict[str, Any]] = {}
    capture_configuration(source, destination, plain, modes, dashboard_pointer=True)
    assert (destination / "dashboard").is_dir()
    assert not (destination / "dashboard").is_symlink()
    assert (destination / "dashboard/index.html").read_text() == "reviewed dashboard"
    assert not any(path.is_symlink() for path in plain.rglob("*"))
    restore_configuration_modes(plain, modes)
    assert stat.S_IMODE((destination / "dashboard").stat().st_mode) == 0o755


@pytest.mark.parametrize("kind", ["absolute", "outside", "release_link", "releases_link", "other"])
def test_dashboard_exception_does_not_allow_unmanaged_or_escaping_links(
    tmp_path: Path, kind: str
) -> None:
    source = tmp_path / "nginx"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("must not enter the backup")
    releases = source / "dashboard-releases"
    release = releases / "release-current"
    if kind == "releases_link":
        releases.symlink_to(outside, target_is_directory=True)
    else:
        releases.mkdir()
    if kind == "release_link":
        release.symlink_to(outside, target_is_directory=True)
    elif kind != "releases_link":
        release.mkdir()
    if kind == "absolute":
        pointer = release
    elif kind == "outside":
        pointer = Path("../outside")
    else:
        pointer = Path("dashboard-releases/release-current")
    (source / "dashboard").symlink_to(pointer, target_is_directory=True)
    if kind == "other":
        (source / "private.key").symlink_to(outside / "secret")
    plain = tmp_path / "plain"
    plain.mkdir(mode=0o700)
    with pytest.raises(ValueError):
        capture_configuration(
            source, plain / "configuration/nginx", plain, {}, dashboard_pointer=True
        )
    assert not any(
        path.is_file() and path.read_text() == "must not enter the backup"
        for path in plain.rglob("*")
    )


def test_generic_configuration_capture_still_rejects_managed_looking_links(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    release = source / "dashboard-releases/release-current"
    release.mkdir(parents=True)
    (source / "dashboard").symlink_to(
        "dashboard-releases/release-current", target_is_directory=True
    )
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(ValueError, match="Symlink"):
        capture_configuration(source, plain / "configuration/other", plain, {})
