"""Certificate/credential storage is independent from source checkout and mutable data."""

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.infrastructure import secrets, storage
from scripts.infrastructure.manage import load_config, resolved, validate_model


def test_private_mounts_and_tls_snapshots_follow_secrets_base(tmp_path: Path) -> None:
    config = load_config(
        overrides={
            "MOUNT_BASE": str(tmp_path / "data"),
            "SECRETS_BASE": str(tmp_path / "credentials"),
        }
    )
    model = resolved(config)
    private_targets = {
        "/run/cve-api",
        "/run/cve-n8n",
        "/run/cve-ansible",
        "/mail-secrets",
        "/var/run/postgresql/tls",
        "/etc/nginx/cve",
    }
    for service in model["services"].values():
        for mount in service.get("volumes", []):
            if mount["target"] in private_targets:
                assert mount["read_only"]
                assert Path(mount["source"]).is_relative_to(config.secrets_base)
            elif not mount.get("read_only"):
                assert Path(mount["source"]).is_relative_to(config.mount_base)
    assert Path(config.values["TLS_KEY_FILE"]).parent == Path(config.values["TLS_DIR"])
    assert config.directory.is_relative_to(config.secrets_base)
    assert (
        validate_model(model, True, mount_base=config.mount_base, secrets_base=config.secrets_base)
        == []
    )


@pytest.mark.parametrize("value", ["/", "../outside", "/etc;id", "/mnt/a,other"])
def test_unsafe_secret_roots_are_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        load_config(overrides={"SECRETS_BASE": value})


@pytest.mark.parametrize("copy_fails", [False, True])
def test_credentials_are_adopted_without_regeneration_or_overwriting(
    tmp_path: Path,
    repository_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    copy_fails: bool,
) -> None:
    config = load_config(
        repository_root / "configuration/examples/development.env",
        root=tmp_path,
        overrides={"SECRETS_BASE": str(tmp_path / "private")},
    )
    source = tmp_path / ".runtime/services" / config.project
    source.mkdir(parents=True)
    original = source / "auth.key"
    original.write_text("existing-private-value")
    original.chmod(0o600)
    monkeypatch.setattr(secrets, "run", lambda _args: SimpleNamespace(stdout=""))

    def copy(_config: object, arguments: list[str], _command: str) -> None:
        if copy_fails:
            raise subprocess.CalledProcessError(1, "copy")
        target = Path(arguments[1].split("source=", 1)[1].split(",target=", 1)[0])
        shutil.copytree(source, target, dirs_exist_ok=True)

    monkeypatch.setattr(storage, "helper", copy)
    target = config.secrets_base / "services" / config.project
    if copy_fails:
        with pytest.raises(subprocess.CalledProcessError):
            secrets.prepare(config)
        assert not target.exists()
    else:
        secrets.prepare(config)
        assert (target / "auth.key").read_bytes() == original.read_bytes()
        assert (target / "auth.key").stat().st_mode & 0o777 == 0o600
        (target / "auth.key").write_text("updated-private-value")
        secrets.prepare(config)
        assert (target / "auth.key").read_text() == "updated-private-value"
    assert original.read_text() == "existing-private-value"


def test_secret_relocation_requires_stopped_containers(
    tmp_path: Path,
    repository_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config(
        repository_root / "configuration/examples/development.env",
        root=tmp_path,
        overrides={"SECRETS_BASE": str(tmp_path / "private")},
    )
    monkeypatch.setattr(secrets, "run", lambda _args: SimpleNamespace(stdout="running-container"))
    with pytest.raises(ValueError, match="Stack stoppen"):
        secrets.prepare(config)
    assert not config.secrets_base.exists()


def test_server_profile_allows_non_loopback_without_changing_development(
    repository_root: Path,
) -> None:
    config = load_config(repository_root / "configuration/examples/server.env")
    assert config.values["APP_ENV"] == "production"
    assert config.values["INGRESS_BIND_IP"] == "0.0.0.0"
    assert (
        validate_model(
            resolved(config), False, mount_base=config.mount_base, secrets_base=config.secrets_base
        )
        == []
    )
    with pytest.raises(ValueError, match="Loopback"):
        load_config(overrides={"APP_ENV": "development", "INGRESS_BIND_IP": "0.0.0.0"})
