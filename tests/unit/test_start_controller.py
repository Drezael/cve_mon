"""Lifecycle boundaries of the single root entry point; no running services are stopped."""

import importlib.machinery
import importlib.util
import json
import shutil
import subprocess
import sys
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from scripts.infrastructure.manage import load_config


@pytest.fixture
def controller(repository_root: Path) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(
        "cve_start_test", str(repository_root / "cve_mon")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_help_works_outside_the_repository(repository_root: Path, tmp_path: Path) -> None:
    result = subprocess.run(
        [str(repository_root / "cve_mon"), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert all(command in result.stdout for command in ["start", "stop", "logs", "health"])


def test_down_retains_volumes_and_stops_control_first(
    controller: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.automation_executor import agent

    calls: list[Any] = []
    monkeypatch.setattr(agent, "exclusive", lambda _c: nullcontext())
    monkeypatch.setattr(controller, "stop_controller", lambda _c: calls.append("controller"))
    monkeypatch.setattr(controller, "compose", lambda _c, args: calls.append(args))
    controller.stop(load_config(), remove=True)
    assert calls[0] == "controller"
    assert calls[1][0] == "stop" and calls[2][0] == "down"
    assert not any("--volumes" in call or "-v" in call or "prune" in call for call in calls)


def test_shutdown_failure_never_proceeds_to_removing_containers(
    controller: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.automation_executor import agent

    monkeypatch.setattr(agent, "exclusive", lambda _c: nullcontext())
    monkeypatch.setattr(controller, "stop_controller", lambda _c: None)
    calls = []

    def fail(_config: Any, args: list[str]) -> None:
        calls.append(args)
        raise subprocess.CalledProcessError(1, "docker")

    monkeypatch.setattr(controller, "compose", fail)
    with pytest.raises(subprocess.CalledProcessError):
        controller.stop(load_config(), remove=True)
    assert len(calls) == 1 and calls[0][0] == "stop"


def test_foreign_process_in_stale_pidfile_is_never_killed(
    controller: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.automation_executor import agent

    monkeypatch.setattr(agent, "directory", lambda _c: tmp_path)
    monkeypatch.setattr(controller.shutil, "which", lambda _c: None)
    with subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"]) as process:
        try:
            (tmp_path / "agent.pid").write_text(str(process.pid))
            with pytest.raises(controller.LaunchError, match="zugeordnet"):
                controller.stop_controller(load_config())
            assert process.poll() is None
        finally:
            process.terminate()
            process.wait(timeout=5)


def test_logical_log_targets_are_grouped_and_unknown_targets_rejected(
    controller: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def compose(_config: Any, args: list[str]) -> SimpleNamespace:
        calls.append(args)
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(controller, "compose", compose)
    controller.logs(load_config(), ["matcher", "findings"], follow=False, tail=1)
    assert calls[0].count("cve-processing") == 1
    with pytest.raises(controller.LaunchError):
        controller.logs(load_config(), ["nextcloud"], follow=False, tail=1)
    assert len(calls) == 1


@pytest.mark.parametrize("pending_migration", [False, True])
def test_repeated_start_preserves_containers_but_applies_pending_migrations(
    controller: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pending_migration: bool,
) -> None:
    from scripts.application import build

    config = replace(
        load_config(overrides={"MOUNT_BASE": "./.runtime", "SECRETS_BASE": "./.runtime"}),
        root=tmp_path,
    )
    built = tmp_path / "services/dashboard/dist/index.html"
    built.parent.mkdir(parents=True)
    built.write_text("build")
    deployed = config.directory / "dashboard/index.html"
    deployed.parent.mkdir(parents=True)
    deployed.write_text("build")
    # No real build, Docker mutation or database query is performed in this test.
    calls: list[str] = []
    monkeypatch.setattr(controller, "frontend", lambda _c: None)
    monkeypatch.setattr(build, "build", lambda _c: None)
    monkeypatch.setattr(build, "fingerprint", lambda _r: "inputs")
    monkeypatch.setattr(controller, "healthy", lambda _c: True)
    monkeypatch.setattr(controller, "current_schema", lambda _c: not pending_migration)
    monkeypatch.setattr(controller, "current_compose", lambda _c: True)
    monkeypatch.setattr(controller, "workflows_ready", lambda _c: True)
    monkeypatch.setattr(controller, "controller_ready", lambda _c: True)
    monkeypatch.setattr(controller, "provision", lambda _c, **_kwargs: calls.append("provision"))
    monkeypatch.setattr(
        controller, "compose", lambda _c, _args: SimpleNamespace(stdout="one two three")
    )

    def inspect(args: list[str]) -> SimpleNamespace:
        if "image" in args:
            value = [{"Id": "image", "Config": {"Labels": {build.LABEL: "inputs"}}}]
        else:
            value = [{"Image": "image"}] * 3
        return SimpleNamespace(stdout=json.dumps(value))

    monkeypatch.setattr(controller, "run", inspect)
    from scripts.dashboard import manage as dashboard

    monkeypatch.setattr(dashboard, "activate", lambda _c: calls.append("activate"))
    controller.start(config)
    assert ("provision" in calls) == pending_migration


def test_failed_frontend_build_cannot_start_database_or_workers(
    controller: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_config: Any) -> None:
        raise subprocess.CalledProcessError(23, "npm")

    monkeypatch.setattr(controller, "frontend", fail)

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("No services may be started after a failed frontend build")

    monkeypatch.setattr(controller, "provision", forbidden)
    with pytest.raises(subprocess.CalledProcessError):
        controller.start(load_config())


def test_cli_reports_captured_failure_without_arguments_stdout_or_passwords(
    controller: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = load_config(
        overrides={
            "SECRETS_BASE": str(tmp_path),
            "SMTP_PASSWORD": "smtp-secret",  # pragma: allowlist secret
            "CLOUDFLARE_API_TOKEN": "cloudflare-test-token",  # pragma: allowlist secret
        }
    )
    secrets = tmp_path / "database" / config.project / "secrets"
    secrets.mkdir(parents=True)
    (secrets / "postgres_admin.password").write_text("database-secret\n")
    monkeypatch.setattr(controller, "load_config", lambda **_kwargs: config)
    monkeypatch.setattr(controller, "docker_ready", lambda **_kwargs: None)
    monkeypatch.setattr(controller, "own_project", lambda _c: None)
    monkeypatch.setattr(controller, "lifecycle", lambda _c: nullcontext())

    def fail(_config: Any, **_kwargs: Any) -> None:
        raise subprocess.CalledProcessError(
            23,
            ["docker", "argument-secret"],
            output="stdout-secret",
            stderr=(
                "Container cve-postgres failed: database-secret smtp-secret cloudflare-test-token "
                "postgresql://user:url-secret@localhost/db"  # pragma: allowlist secret
            ),
        )

    from scripts.infrastructure import mounts
    from scripts.infrastructure import secrets as secret_locations

    monkeypatch.setattr(mounts, "prepare", lambda _c: None)
    monkeypatch.setattr(secret_locations, "prepare", lambda _c: None)
    monkeypatch.setattr(controller, "start", fail)
    assert controller.main(["start"]) == 1
    diagnostic = capsys.readouterr().err
    assert "Exit-Code 23" in diagnostic
    assert "Container cve-postgres failed" in diagnostic
    for secret in [
        "database-secret",
        "smtp-secret",
        "cloudflare-test-token",
        "url-secret",
        "argument-secret",
        "stdout-secret",
    ]:
        assert secret not in diagnostic


def test_failure_without_stderr_keeps_stdout_private(controller: ModuleType) -> None:
    error = subprocess.CalledProcessError(7, ["docker", "private"], output="private-output")
    message = controller.process_failure(error, None)
    assert "Exit-Code 7" in message
    assert "private" not in message


def test_failure_diagnostic_is_bounded(controller: ModuleType) -> None:
    error = subprocess.CalledProcessError(1, "docker", stderr="x" * 10000)
    assert controller.process_failure(error, None).splitlines()[1] == "x" * 4000


def test_foreign_checkout_with_same_compose_name_is_rejected(
    controller: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def inspect(args: list[str]) -> SimpleNamespace:
        calls.append(args)
        if "inspect" not in args:
            return SimpleNamespace(stdout="foreign")
        return SimpleNamespace(
            stdout=json.dumps(
                [
                    {
                        "Config": {
                            "Labels": {
                                "com.docker.compose.project.working_dir": "/other/project",
                                "com.docker.compose.project.config_files": (
                                    "/other/project/compose.yml"
                                ),
                            }
                        }
                    }
                ]
            )
        )

    monkeypatch.setattr(controller, "run", inspect)
    with pytest.raises(controller.LaunchError, match="anderen Deployment"):
        controller.own_project(load_config())
    assert all("stop" not in call and "down" not in call for call in calls)


@pytest.mark.parametrize("present", [0, 1, 4])
def test_pki_is_created_only_when_empty_and_never_overwritten(
    controller: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    present: int,
) -> None:
    from scripts.infrastructure import manage

    keys = ["TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_TRUST_FILE", "CLIENT_CA_FILE"]
    values = {key: str(tmp_path / key) for key in keys}
    for key in keys[:present]:
        Path(values[key]).write_text("existing key or certificate")
    config = replace(load_config(), values=load_config().values | values)
    called = []
    monkeypatch.setattr(manage, "generate_certificates", lambda _c: called.append(True))
    if present == 1:
        with pytest.raises(controller.LaunchError, match="unvollständig"):
            controller.ensure_certificates(config)
    else:
        controller.ensure_certificates(config)
    assert bool(called) == (present == 0)
    for key in keys[:present]:
        assert Path(values[key]).read_text() == "existing key or certificate"


@pytest.mark.parametrize("confirmation", [None, "wrong-project"])
def test_reset_requires_project_confirmation_before_docker(
    controller: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    confirmation: str | None,
) -> None:
    def forbidden(**_kwargs: Any) -> None:
        pytest.fail("Unconfirmed reset must not access Docker")

    monkeypatch.setattr(controller, "docker_ready", forbidden)
    args = ["reset"] + (["--confirm", confirmation] if confirmation else [])
    assert controller.main(args) == 1
    assert "reset --confirm " + load_config().project in capsys.readouterr().err


def test_reset_is_project_scoped_and_preserves_lock_files(
    controller: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.automation_executor import agent
    from scripts.infrastructure import storage

    monkeypatch.setattr(storage, "remove", lambda c: shutil.rmtree(storage.directory(c)))

    config = replace(
        load_config(
            overrides={
                "MOUNT_BASE": str(tmp_path / ".runtime"),
                "SECRETS_BASE": str(tmp_path / ".runtime"),
            }
        ),
        root=tmp_path,
    )
    paths = controller.reset_paths(config)
    for path in paths:
        path.mkdir(parents=True)
        (path / "data").write_text("data")
    locks = [
        tmp_path / ".runtime/application" / config.project / "lifecycle.lock",
        tmp_path / ".runtime/automation-executor" / config.project / "erasure.lock",
    ]
    for lock in locks:
        lock.write_text("lock")
    preserved = [
        tmp_path / ".env",
        tmp_path / ".runtime/database/other/data",
        tmp_path / ".runtime/development/pki/server.key",
        tmp_path / ".runtime/manual-backup/data",
    ]
    for path in preserved:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("preserve")
    calls: list[Any] = []
    monkeypatch.setattr(agent, "exclusive", lambda _c: nullcontext())
    monkeypatch.setattr(controller, "own_project", lambda _c: calls.append("ownership"))
    monkeypatch.setattr(controller, "reset_volumes", lambda _c: ["own-volume"])
    monkeypatch.setattr(controller, "stop_controller", lambda _c: calls.append("controller"))
    monkeypatch.setattr(controller, "compose", lambda _c, args: calls.append(args))
    monkeypatch.setattr(controller, "run", lambda args: calls.append(args))
    controller.reset(config, confirmation=config.project)
    assert calls[1] == "controller"
    assert calls[2][0] == "stop" and calls[3][0] == "down"
    assert calls[4][-3:] == ["volume", "rm", "own-volume"]
    assert all(path.read_text() == "preserve" for path in preserved)
    assert all(lock.read_text() == "lock" for lock in locks)
    assert all(not (path / "data").exists() for path in paths)
    assert all(not path.exists() for path in paths if path not in [p.parent for p in locks])


@pytest.mark.parametrize("failure", ["controller", "stop", "down"])
def test_reset_aborts_before_deletion_after_shutdown_failure(
    controller: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    from scripts.automation_executor import agent

    config = replace(
        load_config(
            overrides={
                "MOUNT_BASE": str(tmp_path / ".runtime"),
                "SECRETS_BASE": str(tmp_path / ".runtime"),
            }
        ),
        root=tmp_path,
    )
    sentinel = tmp_path / ".runtime/services" / config.project / "data"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text("keep")
    monkeypatch.setattr(agent, "exclusive", lambda _c: nullcontext())
    monkeypatch.setattr(controller, "own_project", lambda _c: None)
    monkeypatch.setattr(controller, "reset_volumes", lambda _c: [])

    def shutdown(_c: Any, args: list[str] | None = None) -> None:
        if (args[0] if args else "controller") == failure:
            raise subprocess.CalledProcessError(1, "shutdown")

    monkeypatch.setattr(controller, "stop_controller", shutdown)
    monkeypatch.setattr(controller, "compose", shutdown)
    with pytest.raises(subprocess.CalledProcessError):
        controller.reset(config, confirmation=config.project)
    assert sentinel.read_text() == "keep"


@pytest.mark.parametrize("foreign", [True, False])
def test_reset_checks_volume_ownership(
    controller: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    foreign: bool,
) -> None:
    config = load_config()
    name = config.project + "_postgres_data"

    def docker(args: list[str]) -> SimpleNamespace:
        if "ls" in args:
            return SimpleNamespace(stdout=name + "\nunrelated-volume\n")
        return SimpleNamespace(
            stdout=json.dumps(
                [
                    {
                        "Labels": {
                            "com.docker.compose.project": "foreign" if foreign else config.project,
                            "com.docker.compose.volume": "postgres_data",
                        }
                    }
                ]
            )
        )

    monkeypatch.setattr(controller, "run", docker)
    if foreign:
        with pytest.raises(controller.LaunchError, match="Fremdes Volume"):
            controller.reset_volumes(config)
    else:
        assert controller.reset_volumes(config) == [name]


@pytest.mark.parametrize("unsafe", ["symlink", "external", "runtime-root", "overlap"])
def test_reset_rejects_unsafe_paths(
    controller: ModuleType,
    tmp_path: Path,
    unsafe: str,
) -> None:
    base = tmp_path / ".runtime/database"
    if unsafe == "external":
        base = tmp_path / "outside"
    elif unsafe == "runtime-root":
        base = tmp_path / ".runtime"
    elif unsafe == "overlap":
        base = tmp_path / ".runtime/services" / load_config().project / "nested"
    config = replace(
        load_config(overrides={"MOUNT_BASE": "./.runtime", "SECRETS_BASE": "./.runtime"}),
        root=tmp_path,
    )
    config = replace(config, values=config.values | {"PG_WORK_DIR": str(base)})
    if unsafe == "symlink":
        target = tmp_path / ".runtime/services"
        target.parent.mkdir()
        target.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(controller.LaunchError):
        controller.reset_paths(config)


def test_reset_rejects_production(controller: ModuleType) -> None:
    config = load_config()
    config = replace(config, values=config.values | {"APP_ENV": "production"})
    with pytest.raises(controller.LaunchError, match="Entwicklungsprojekte"):
        controller.reset(config, confirmation=config.project)


def test_external_reset_targets_data_and_private_config_but_preserves_repository_sources(
    controller: ModuleType,
    tmp_path: Path,
    repository_root: Path,
) -> None:
    root = tmp_path / "checkout"
    config = load_config(
        repository_root / "configuration/examples/development.env",
        root=root,
        overrides={
            "MOUNT_BASE": str(tmp_path / "data"),
            "SECRETS_BASE": str(root / ".runtime"),
        },
    )
    paths = controller.reset_paths(config)
    assert config.mount_base / "storage" / config.project in paths
    assert config.mount_base / "n8n" / config.project / "data" in paths
    assert root / ".runtime/services" / config.project in paths
    assert not any(
        (root / "infrastructure/postgres/postgresql.conf").is_relative_to(p) for p in paths
    )
    assert not any((config.mount_base / "n8n/other-project/data").is_relative_to(p) for p in paths)


def test_server_start_is_supported_by_public_entrypoint(
    controller: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.infrastructure import mounts
    from scripts.infrastructure import secrets as secret_locations

    config = load_config(overrides={"APP_ENV": "production", "INGRESS_BIND_IP": "0.0.0.0"})
    monkeypatch.setattr(controller, "load_config", lambda **_kwargs: config)
    monkeypatch.setattr(controller, "docker_ready", lambda **_kwargs: None)
    monkeypatch.setattr(controller, "own_project", lambda _c: None)
    monkeypatch.setattr(controller, "lifecycle", lambda _c: nullcontext())
    monkeypatch.setattr(mounts, "prepare", lambda _c: None)
    monkeypatch.setattr(secret_locations, "prepare", lambda _c: None)
    calls = []
    monkeypatch.setattr(controller, "start", lambda _c, **_kw: calls.append("start"))
    assert controller.main(["start"]) == 0
    assert calls == ["start"]


def test_server_never_generates_missing_ingress_certificates(
    controller: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.infrastructure import manage

    config = load_config(
        overrides={"APP_ENV": "production", "SECRETS_BASE": str(tmp_path / "private")}
    )

    def forbidden(_config: object) -> None:
        pytest.fail("Production ingress certificates must be supplied by the operator")

    from scripts.infrastructure import storage

    def missing(*_args: Any, **_kwargs: Any) -> None:
        raise subprocess.CalledProcessError(1, "missing-certificate-source")

    monkeypatch.setattr(storage, "helper", missing)
    monkeypatch.setattr(manage, "generate_certificates", forbidden)
    with pytest.raises(controller.LaunchError, match="fullchain.pem und privkey.pem"):
        controller.ensure_certificates(config)


def test_server_rejects_development_pki_before_build_or_start(
    controller: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.database import manage as db
    from scripts.infrastructure import manage

    config = load_config(overrides={"APP_ENV": "production", "SECRETS_BASE": str(tmp_path)})
    marker = db.workdir(config) / "private/development.json"
    marker.parent.mkdir(parents=True)
    marker.write_text("{}")
    monkeypatch.setattr(controller, "ensure_certificates", lambda _c: None)
    monkeypatch.setattr(manage, "certificate_preflight", lambda _c: None)
    monkeypatch.setattr(db, "prepare", lambda _c: None)

    def forbidden(_config: object) -> None:
        pytest.fail("A development PKI must be rejected before a build or container start")

    monkeypatch.setattr(controller, "frontend", forbidden)
    with pytest.raises(controller.LaunchError, match="Entwicklungs-PKI"):
        controller.start(config)


@pytest.mark.parametrize("difference", [None, "missing", "name", "settings", "unpublished"])
def test_start_detects_changed_repository_workflows(
    controller: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    difference: str | None,
) -> None:
    from unittest.mock import MagicMock

    from scripts.database import manage as db

    config = load_config()
    rows = []
    for path in (config.root / "workflows/n8n").glob("*.json"):
        source = json.loads(path.read_text())
        rows.append(
            {
                "id": source["id"],
                **{key: source[key] for key in ("name", "nodes", "connections")},
                "settings": dict(source.get("settings", {})),
                "active": True,
                "versionId": "published-version",
                "activeVersionId": "published-version",
            }
        )
    if difference == "missing":
        rows.pop()
    elif difference == "name":
        rows[0]["name"] = "older name"
    elif difference == "settings":
        key = next(iter(rows[0]["settings"]))
        rows[0]["settings"][key] = "older setting"
    elif difference == "unpublished":
        rows[0]["activeVersionId"] = None
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = {"name": "workflow_entity"}
    connection.execute.return_value.fetchall.return_value = rows
    context = MagicMock()
    context.__enter__.return_value = connection
    monkeypatch.setattr(db, "connect", lambda *_a, **_kw: context)
    assert controller.workflows_ready(config) is (difference is None)


def test_start_help_has_no_workflow_initialization_option(repository_root: Path) -> None:
    result = subprocess.run(
        [str(repository_root / "cve_mon"), "start", "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "initialize-workflows" not in result.stdout


@pytest.mark.parametrize("foreign", [False, True])
def test_shared_controller_stop_checks_user_unit_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, foreign: bool
) -> None:
    from scripts.automation_executor import agent

    config = load_config(overrides={"COMPOSE_PROJECT_NAME": "cve-db-test-control-stop"})
    calls: list[list[str]] = []
    monkeypatch.setattr(agent, "directory", lambda _c: tmp_path)
    monkeypatch.setattr(shutil, "which", lambda _name: "systemctl")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 0, "", ""),
    )

    def run(args: list[str]) -> SimpleNamespace:
        calls.append(args)
        return SimpleNamespace(stdout="/foreign" if foreign else str(config.root))

    monkeypatch.setattr(agent, "run", run)
    if foreign:
        with pytest.raises(ValueError, match="Arbeitsverzeichnis"):
            agent.stop(config)
        assert not any("stop" in args for args in calls)
    else:
        agent.stop(config)
        assert calls[-1] == [
            "systemctl",
            "--user",
            "stop",
            "cve-automation-control-" + config.project,
        ]
