"""Only mutable data follows MOUNT_BASE; read-only inputs stay inside the repository."""

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.infrastructure import mounts, storage
from scripts.infrastructure.manage import load_config, resolved, validate_model


def test_custom_base_controls_mutable_data_and_preserves_repository_inputs(tmp_path: Path) -> None:
    config = load_config(overrides={"MOUNT_BASE": str(tmp_path / "mounts")})
    model = resolved(config)
    outside = []
    inside = []
    for service in model["services"].values():
        for mount in service.get("volumes", []):
            if not mount.get("read_only"):
                assert Path(mount["source"]).is_relative_to(config.mount_base)
                outside.append(mount["source"])
            elif Path(mount["source"]).is_relative_to(config.root):
                inside.append(mount["source"])
            else:
                # Shared status is mutable data written by Postfix and observed by the API.
                assert mount["target"] == "/run/cve-status/postfix"
    assert outside and inside
    for secret in model["secrets"].values():
        assert Path(secret["file"]).is_relative_to(config.root / ".runtime")
    assert Path(config.values["PG_WORK_DIR"]) == config.root / ".runtime/database"
    assert config.directory == config.root / ".runtime/nginx" / config.project
    assert validate_model(model, True, mount_base=config.mount_base) == []


@pytest.mark.parametrize("base", ["", "/", "/mnt/../etc", "../other", "/mnt;id", "/mnt,$HOME"])
def test_invalid_mount_bases_are_rejected(base: str) -> None:
    with pytest.raises(ValueError):
        load_config(overrides={"MOUNT_BASE": base})


def test_relocation_preserves_old_files_and_skips_existing_targets(
    tmp_path: Path,
    repository_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config(
        repository_root / "configuration/examples/development.env",
        root=tmp_path,
        overrides={
            "MOUNT_BASE": str(tmp_path / "mounts"),
            "COMPOSE_PROJECT_NAME": "cve-test-relocation",
        },
    )
    old = tmp_path / ".runtime/n8n" / config.project / "data"
    old.mkdir(parents=True)
    (old / "key").write_text("retained")
    (old / "key").chmod(0o600)
    monkeypatch.setattr(mounts, "run", lambda _args: SimpleNamespace(stdout=""))
    copies = []

    def copy(_config: object, arguments: list[str], _command: str) -> None:
        source = Path(arguments[0].split("source=", 1)[1].split(",target=", 1)[0])
        destination = Path(arguments[1].split("source=", 1)[1].split(",target=", 1)[0])
        copies.append(source)
        shutil.copytree(source, destination, dirs_exist_ok=True)

    monkeypatch.setattr(storage, "helper", copy)
    readonly = tmp_path / ".runtime/services" / config.project
    readonly.mkdir(parents=True)
    (readonly / "config.key").write_text("private")
    # Source configuration files remain inside this fixture checkout.
    for relative in (
        "nginx/nginx.conf",
        "postgres/postgresql.conf",
        "postgres/pg_hba.conf",
        "postgres/pg_ident.conf",
    ):
        source = tmp_path / "infrastructure" / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("configuration")
    for relative in ("postgres/initdb", "postgres/health", "mail", "status"):
        (tmp_path / "infrastructure" / relative).mkdir(parents=True, exist_ok=True)
    mounts.prepare(config)
    target = config.mount_base / "n8n" / config.project / "data/key"
    assert target.read_text() == (old / "key").read_text() == "retained"
    assert target.stat().st_mode & 0o777 == 0o600
    target.write_text("new state")
    mounts.prepare(config)
    assert target.read_text() == "new state" and len(copies) == 1
    marker = tmp_path / ".runtime/mount-locations" / (config.project + ".json")
    assert json.loads(marker.read_text())["mount_base"] == str(config.mount_base)
    assert not (config.mount_base / "services").exists()
    assert (readonly / "config.key").read_text() == "private"


def test_relocation_rejects_running_source_before_writing(
    tmp_path: Path,
    repository_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config(
        repository_root / "configuration/examples/development.env",
        root=tmp_path,
        overrides={"MOUNT_BASE": str(tmp_path / "mounts")},
    )
    monkeypatch.setattr(mounts, "run", lambda _args: SimpleNamespace(stdout="running-container"))
    with pytest.raises(ValueError, match="Stack stoppen"):
        mounts.prepare(config)
    assert not config.mount_base.exists()
