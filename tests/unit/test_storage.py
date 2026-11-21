"""Bind storage adoption must preserve originals and reject live or foreign sources."""

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.infrastructure import storage
from scripts.infrastructure.manage import Config, load_config


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return replace(
        load_config(overrides={"MOUNT_BASE": "./.runtime", "SECRETS_BASE": "./.runtime"}),
        root=tmp_path,
    )


@pytest.mark.parametrize("problem", [None, "foreign", "active", "copy-failed"])
def test_legacy_adoption_is_offline_and_publishes_only_complete_copy(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
    problem: str | None,
) -> None:
    logical = "cve_mailhog_data"
    name = config.project + "_" + logical
    commands: list[list[str]] = []
    helpers: list[list[str]] = []

    def docker(command: list[str]) -> SimpleNamespace:
        commands.append(command)
        if "ls" in command:
            return SimpleNamespace(stdout=name)
        if "inspect" in command:
            return SimpleNamespace(
                stdout=json.dumps(
                    [
                        {
                            "Labels": {
                                "com.docker.compose.project": "foreign"
                                if problem == "foreign"
                                else config.project,
                                "com.docker.compose.volume": logical,
                            }
                        }
                    ]
                )
            )
        return SimpleNamespace(stdout="active-container" if problem == "active" else "")

    def copy(_config: Config, mounts: list[str], _command: str) -> None:
        helpers.append(mounts)
        if problem == "copy-failed":
            raise subprocess.CalledProcessError(1, "copy")
        (storage.directory(config) / ".migrating-mailhog/message").write_text("retained")

    monkeypatch.setattr(storage, "run", docker)
    monkeypatch.setattr(storage, "helper", copy)
    if problem:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            storage.prepare(config, ["cve-mailhog"])
        assert not storage.path(config, logical).exists()
        assert bool(helpers) == (problem == "copy-failed")
    else:
        storage.prepare(config, ["cve-mailhog"])
        assert (storage.path(config, logical) / "message").read_text() == "retained"
        assert helpers[0][0] == "type=volume,source=" + name + ",target=/legacy,readonly"
        storage.prepare(config, ["cve-mailhog"])
        assert len(helpers) == 1
    assert all("rm" not in c and "create" not in c for c in commands)


def test_new_store_prepares_mailhog_owner_without_creating_volumes(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage, "run", lambda _args: SimpleNamespace(stdout=""))
    commands: list[str] = []
    monkeypatch.setattr(storage, "helper", lambda _c, _m, command: commands.append(command))
    storage.prepare(config, ["cve-postgres", "cve-mail-relay", "cve-mailhog"])
    assert all(storage.path(config, key).is_dir() for key in storage.STORES)
    assert commands == ["chown postgres:postgres /target", "chown 1000:1000 /target"]
    assert storage.path(config, "cve_postfix_queue").stat().st_mode & 0o777 == 0o755


def test_storage_rejects_symlink_parent(config: Config, tmp_path: Path) -> None:
    (tmp_path / ".runtime").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        storage.checked(config)


def test_queue_backup_rejects_unrelated_bind(config: Config) -> None:
    from scripts.infrastructure.mail import queue_bind

    with pytest.raises(ValueError, match="Foreign"):
        queue_bind(
            config,
            {
                "Mounts": [
                    {"Destination": "/var/spool/postfix", "Type": "bind", "Source": "/unrelated"}
                ]
            },
        )


def test_image_volume_declarations_use_tmpfs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        storage,
        "run",
        lambda _args: SimpleNamespace(
            stdout=json.dumps([{"Config": {"Volumes": {"/var/lib/postgresql": {}}}}])
        ),
    )
    assert storage.image_tmpfs("image") == [
        "--tmpfs",
        "/var/lib/postgresql:rw,noexec,nosuid,size=16m",
    ]
