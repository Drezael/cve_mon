"""Daemonunabhängige Schutzgrenzen der PostgreSQL-Operatorwerkzeuge."""

from pathlib import Path

import pytest
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory

from scripts.database.manage import cleanup_test, prepare, read_secret
from scripts.infrastructure.manage import load_config


@pytest.mark.parametrize("content", ["short", "x" * 40 + "\n\n", "x" * 40 + "\nsecond", "x" * 257])
def test_invalid_secret_file(tmp_path: Path, content: str) -> None:
    file = tmp_path / "credential"
    file.write_text(content)
    file.chmod(0o600)
    with pytest.raises(ValueError):
        read_secret(file)


def test_secret_file_permissions_and_symlink(tmp_path: Path) -> None:
    file = tmp_path / "credential"
    file.write_text("x" * 40 + "\n")
    file.chmod(0o644)
    with pytest.raises(ValueError):
        read_secret(file)
    file.chmod(0o600)
    assert read_secret(file) == "x" * 40
    link = tmp_path / "link"
    link.symlink_to(file)
    with pytest.raises(ValueError):
        read_secret(link)


def test_no_automatic_production_secrets_or_data_deletion(tmp_path: Path) -> None:
    config = load_config(
        overrides={
            "APP_ENV": "production",
            "SECRETS_BASE": str(tmp_path),
            "COMPOSE_PROJECT_NAME": "cve-prod-probe",
        }
    )
    with pytest.raises(ValueError, match="Produktion"):
        prepare(config)
    with pytest.raises(ValueError, match="Datenlöschung"):
        cleanup_test(config)
    assert list(tmp_path.iterdir()) == []


def test_single_linear_migration_chain(repository_root: Path) -> None:
    script = ScriptDirectory.from_config(
        AlembicConfig(str(repository_root / "database/alembic.ini"))
    )
    revisions = list(script.walk_revisions())
    assert len(script.get_heads()) == 1 and len(revisions) == 77
    assert revisions[-1].revision == "0001_foundation"


def test_existing_development_credentials_survive_workflow_identity_upgrade(tmp_path: Path) -> None:
    from scripts.database.manage import LOGIN_ROLES, secret_file, workdir

    config = load_config(overrides={"SECRETS_BASE": str(tmp_path)})
    secret_file(config, "postgres_admin").parent.mkdir(parents=True)
    old_roles = ["postgres_admin", *(r for r in LOGIN_ROLES if r != "workflow_control")]
    before = {}
    for role in old_roles:
        path = secret_file(config, role)
        path.write_text("x" * 48 + "\n")
        path.chmod(0o600)
        before[role] = path.read_bytes()
    tls = workdir(config) / "tls"
    tls.mkdir()
    for name in ("server.crt", "server.key", "ca.crt"):
        (tls / name).touch()
    prepare(config)
    control = read_secret(secret_file(config, "workflow_control"))
    assert len(control) >= 48
    prepare(config)
    assert read_secret(secret_file(config, "workflow_control")) == control
    assert all(secret_file(config, role).read_bytes() == value for role, value in before.items())


@pytest.mark.parametrize("stop_fails", [False, True])
def test_test_cleanup_stops_owned_control_before_removing_resources(
    monkeypatch: pytest.MonkeyPatch, stop_fails: bool
) -> None:
    from scripts.automation_executor import agent
    from scripts.database import manage
    from scripts.infrastructure import storage

    config = load_config(overrides={"COMPOSE_PROJECT_NAME": "cve-db-test-cleanup-order"})
    calls: list[str] = []

    def stop(_config: object) -> None:
        calls.append("control")
        if stop_fails:
            raise ValueError("Controller ownership could not be verified")

    monkeypatch.setattr(agent, "stop", stop)
    monkeypatch.setattr(manage, "compose", lambda _c, args: calls.append(args[0]))
    monkeypatch.setattr(storage, "remove", lambda _c: calls.append("storage"))
    if stop_fails:
        with pytest.raises(ValueError, match="ownership"):
            manage.cleanup_test(config)
        assert calls == ["control"]
    else:
        manage.cleanup_test(config)
        assert calls == ["control", "down", "storage"]
