"""Private local management socket. No arbitrary commands, SQL, paths or Docker targets."""

import argparse
import asyncio
import contextlib
import fcntl
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg

from scripts.database import manage as db
from scripts.deployment.contracts import atomic
from scripts.infrastructure.manage import Config, compose, docker_command, run


def directory(config: Config) -> Path:
    return config.secrets_base / "automation-executor" / config.project


def prepare(config: Config) -> None:
    base = directory(config)
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    service = config.secrets_base / "services" / config.project
    service.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = service / "control.token"
    if not token.exists():
        token.write_text(secrets.token_urlsafe(32))
        token.chmod(0o600)
    atomic(base / "agent-config.json", {"root": str(config.root), "values": config.values})
    if not (base / "generation.json").exists():
        atomic(base / "generation.json", {"generation": 0})


_LOCAL = threading.local()


@contextlib.contextmanager
def exclusive(config: Config) -> Iterator[None]:
    """Serialize snapshots and erasure; permit nested snapshot helpers in one thread."""
    active: set[str] = getattr(_LOCAL, "active", set())
    identity = str(directory(config).resolve())
    if identity in active:
        yield
        return
    prepare(config)
    with (directory(config) / "erasure.lock").open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        _LOCAL.active = active | {identity}
        try:
            yield
        finally:
            _LOCAL.active = active


@contextlib.contextmanager
def shared_operation(config: Config) -> Iterator[None]:
    """Independent process restarts may overlap; snapshots and erasure stay exclusive."""
    base = directory(config)
    if str(base.resolve()) in getattr(_LOCAL, "active", set()):
        yield
        return
    base.mkdir(parents=True, mode=0o700, exist_ok=True)
    with (base / "erasure.lock").open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_SH)
        yield


def generation(config: Config) -> int:
    path = directory(config) / "generation.json"
    return json.loads(path.read_text())["generation"] if path.exists() else 0


def backup_project(path: Path) -> str | None:
    """Foreign or malformed discovery metadata cannot block this project's cleanup."""
    try:
        if path.is_symlink() or path.stat().st_size > 262144:
            return None
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, ValueError):
        return None
    project = value.get("project") if isinstance(value, dict) else None
    return project if isinstance(project, str) else None


def purge_managed_backups(config: Config) -> int:
    """Only snapshots with an explicit project manifest and local key reference qualify."""
    runtime = config.root / ".runtime"
    # Adopt older snapshots only when their own manifest explicitly names this project.
    for pattern in ("*/manifest.json", "*/*/manifest.json"):
        for manifest in runtime.glob(pattern):
            try:
                value = json.loads(manifest.read_text())
                if not isinstance(value, dict) or value.get("project") != config.project:
                    continue
                backup = manifest.parent
                if backup.is_symlink() or not backup.resolve().is_relative_to(runtime):
                    continue
                if not any(backup.glob("*.dump")) and not any(backup.glob("*.enc")):
                    continue
                key = Path(value["key_file"]) if value.get("key_file") else None
                register_backup(config, backup, key)
            except (OSError, UnicodeError, ValueError):
                continue
    removed = 0
    for pointer in (config.root / ".runtime").glob("*backup-latest.json"):
        owned = False
        try:
            value = json.loads(pointer.read_text())
            if not isinstance(value, dict) or not isinstance(value.get("backup"), str):
                continue
            backup = Path(value["backup"])
            if not backup.resolve().is_relative_to(config.root / ".runtime"):
                continue
            manifest = backup / "manifest.json"
            if backup_project(manifest) != config.project:
                continue
            owned = True
            # Unrelated/legacy pointers need not carry this project's key metadata.
            # Registered snapshots are removed by the scoped registry below.
            if not value.get("key_file"):
                continue
            key = Path(value["key_file"])
            if not key.resolve().is_relative_to(config.root / ".runtime"):
                continue
            # A namespace of timestamped snapshots shares this manifest format.
            for folder in backup.parent.iterdir():
                if not folder.is_dir() or folder.is_symlink():
                    continue
                m = folder / "manifest.json"
                if backup_project(m) != config.project:
                    continue
                old_key = key.with_name(key.name.replace(backup.name, folder.name))
                if old_key != key and backup.name in key.name:
                    old_key.unlink(missing_ok=True)
                shutil.rmtree(folder)
                removed += 1
            key.unlink(missing_ok=True)
            pointer.unlink(missing_ok=True)
        except (OSError, ValueError, KeyError):
            if owned:
                raise RuntimeError("managed_backup_erasure_failed") from None
    # Standard deployment/hardening snapshots are registered when created.
    registry = directory(config) / "backups.json"
    if registry.exists():
        for entry in json.loads(registry.read_text()):
            backup = Path(entry["path"])
            registered_key = Path(entry["key"]) if entry.get("key") else None
            if not backup.resolve().is_relative_to(config.root) or (
                registered_key is not None
                and not registered_key.resolve().is_relative_to(config.root)
            ):
                raise ValueError("backup_scope_denied")
            if registered_key is not None:
                registered_key.unlink(missing_ok=True)
            if backup.is_dir() and not backup.is_symlink():
                shutil.rmtree(backup)
                removed += 1
        atomic(registry, [])
    return removed


def register_backup(config: Config, path: Path, key: Path | None = None) -> None:
    if not path.resolve().is_relative_to(config.root):
        return
    prepare(config)
    registry = directory(config) / "backups.json"
    entries = json.loads(registry.read_text()) if registry.exists() else []
    item = {
        "path": str(path.resolve()),
        "key": str(key.resolve()) if key else None,
        "generation": generation(config),
    }
    if item not in entries:
        entries.append(item)
    atomic(registry, entries)


def erase(config: Config, value: dict[str, Any]) -> dict[str, Any]:
    try:
        result = _erase_once(config, value)
    except Exception as error:
        fail_erasure(config, value["request_id"], error)
        raise
    if result["status"] != 204:
        reason = {412: "VERSION_CONFLICT", 404: "SERVER_UNAVAILABLE"}.get(
            result["status"], "DELETION_PAUSED"
        )
        fail_erasure(config, value["request_id"], reason)
    return result


def _erase_once(config: Config, value: dict[str, Any]) -> dict[str, Any]:
    server, actor = UUID(value["server_id"]), UUID(value["actor_id"])
    expected = int(value["version"])
    base = directory(config)
    receipt = base / "erase-receipts" / (str(UUID(value["request_id"])) + ".json")
    binding = hashlib.sha256(
        json.dumps(
            {"server": str(server), "actor": str(actor), "version": expected}, sort_keys=True
        ).encode()
    ).hexdigest()
    if receipt.exists():
        saved = json.loads(receipt.read_text())
        if saved.get("binding") != binding:
            return {"status": 409}
        return {"status": 204}
    operation = base / ("erase-" + str(UUID(value["request_id"])) + ".json")
    if not operation.exists():
        atomic(
            operation,
            {
                "server_id": str(server),
                "actor_id": str(actor),
                "version": expected,
                "phase": "requested",
            },
        )
    if (base / "erasure-paused.json").exists():
        return {"status": 503}
    state = json.loads(operation.read_text())
    if (state.get("server_id"), state.get("actor_id"), state.get("version")) != (
        str(server),
        str(actor),
        expected,
    ):
        return {"status": 409}
    if state.get("phase") == "failed":
        return {"status": 503}
    lock = base / "erasure.lock"
    with lock.open("a+") as control:
        fcntl.flock(control, fcntl.LOCK_EX)
        ids = state.get("owned_ids", [])
        executions = state.get("executions", [])
        runs = state.get("runs", [])
        mail = state.get("mail", [])
        with db.connect(config, "dashboard_admin") as s:
            s.execute("SET LOCAL statement_timeout='30s'")
            s.execute("SELECT set_config('cve.erasure_expected_version',%s,true)", (str(expected),))
            current = s.execute(
                "SELECT version FROM inventory.servers WHERE id=%s", (server,)
            ).fetchone()
            if current:
                if current["version"] != expected:
                    return {"status": 412}
                s.execute(
                    "SELECT inventory.erase_server(%s,%s) AS removed", (server, actor)
                ).fetchone()
                ids = [
                    r["id"] for r in s.execute("SELECT id FROM pg_temp.server_purge_ids").fetchall()
                ]
                executions = [
                    r["id"] for r in s.execute("SELECT id FROM pg_temp.server_purge_n8n").fetchall()
                ]
                runs = [
                    row["key"]["id"]
                    for row in s.execute(
                        "SELECT key FROM pg_temp.server_purge_rows WHERE rel='inventory.an"
                        "sible_runs'::regclass"
                    ).fetchall()
                ]
                mail = [
                    row["queue_id"]
                    for row in s.execute(
                        "SELECT queue_id FROM pg_temp.server_purge_mail"
                    ).fetchall()
                ]
                state.update(
                    owned_ids=ids,
                    executions=executions,
                    runs=runs,
                    mail=mail,
                    phase="database_erased",
                )
                atomic(operation, state)
            elif state["phase"] == "requested":
                return {"status": 404}
        if state.get("generation") is None:
            next_generation = generation(config) + 1
            atomic(base / "generation.json", {"generation": next_generation})
            state["generation"] = next_generation
            atomic(operation, state)
        with db.connect(config, database="n8n") as s:
            for execution in executions:
                if not str(execution).isdigit():
                    continue
                with db.connect(config) as domain:
                    shared = domain.execute(
                        "SELECT 1 WHERE EXISTS(SELECT 1 FROM automation.workflow_requests "
                        "WHERE execution_id=%s) OR EXISTS(SELECT 1 FROM automation.n8n_queue "
                        "WHERE execution_id=%s)",
                        (str(execution), str(execution)),
                    ).fetchone()
                if not shared:
                    s.execute("DELETE FROM execution_entity WHERE id=%s", (str(execution),))
                else:
                    for ident in ids:
                        s.execute(
                            "UPDATE execution_data SET data=replace(data,%s,'removed') WHERE \""
                            'executionId"=%s',
                            (ident, str(execution)),
                        )
        purge_managed_backups(config)
        if mail:
            import re

            from scripts.infrastructure.mail import container as mail_container

            relay = mail_container(config)["Id"]
            for queue_id in mail:
                if not re.fullmatch(r"[A-Za-z0-9]{5,64}", queue_id):
                    raise ValueError("invalid_queue_id")
                run([*docker_command(), "exec", relay, "postsuper", "-d", queue_id])
        if runs:
            executor = compose(config, ["ps", "-q", "cve-sources"], managed=False).stdout.strip()
            if executor:
                deadline = time.monotonic() + 15
                while True:
                    result = subprocess.run(
                        [
                            *docker_command(),
                            "exec",
                            executor,
                            "python",
                            "-m",
                            "cve_automation.cleanup",
                            *runs,
                        ],
                        capture_output=True,
                        check=False,
                    )
                    if result.returncode == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("executor_cleanup_pending")
                    time.sleep(0.5)
        atomic(receipt, {"actor_id": str(actor), "binding": binding, "state": "completed"})
        operation.unlink(missing_ok=True)
        return {"status": 204}


def erasure_status(config: Config, value: dict[str, Any]) -> dict[str, Any]:
    """Read-only receipt lookup, bound to the authenticated original requesting account."""
    identity = str(UUID(value["request_id"]))
    actor = str(UUID(value["actor_id"]))
    base = directory(config)
    candidates = [
        base / "erase-receipts" / (identity + ".json"),
        base / ("erase-" + identity + ".json"),
        base / "deferred-erasure" / ("erase-" + identity + ".json"),
    ]
    for path in candidates:
        if path.is_symlink():
            raise ValueError("unsafe_receipt")
        if not path.is_file():
            continue
        saved = json.loads(path.read_text())
        if saved.get("actor_id") != actor:
            return {"status": 404}
        state = saved.get("state") or ("failed" if saved.get("phase") == "failed" else "running")
        return {"status": 200, "state": state}
    return {"status": 404}


ERASURE_FAILURES = {
    "CRITICAL_DEADLINE": "Die Zeitgrenze für den koordinierten Löschabschnitt wurde überschritten.",
    "DATABASE_CANCELLED": "Datenbank-Zeitgrenze überschritten oder Löschversuch abgebrochen.",
    "RESOURCE_BUSY": "Benötigte Datensätze oder Koordinationssperren waren belegt.",
    "VERSION_CONFLICT": "Die Serverversion wurde seit der Bestätigung geändert.",
    "DEPENDENCY_CONFLICT": "Abhängige Datensätze konnten nicht konsistent entfernt werden.",
    "AUTHORIZATION_REVOKED": "Die erforderliche Berechtigung ist nicht mehr vorhanden.",
    "BACKUP_ERASURE_FAILED": "Die Bereinigung verwalteter Sicherungen ist fehlgeschlagen.",
    "WORKER_CLEANUP_FAILED": "Die Bereinigung des Erfassungsdienstes wurde nicht bestätigt.",
    "CONNECTION_OR_FILESYSTEM": "Verbindungs- oder Dateisystemfehler beim Löschen.",
    "INTERRUPTED": "Der Controller wurde vor Abschluss des Löschauftrags beendet.",
    "DATABASE_CONTENTION": "Blockierende Datenbankzugriffe haben den Löschauftrag beendet.",
    "DELETION_PAUSED": "Die Löschung wurde während der Fehlerbehebung kontrolliert abgebrochen.",
    "SERVER_UNAVAILABLE": "Der angeforderte Server ist nicht mehr verfügbar.",
    "UNEXPECTED_FAILURE": "Ein unerwarteter interner Fehler hat den Löschauftrag beendet.",
}


def fail_erasure(config: Config, request_id: str, error: Exception | str) -> None:
    base = directory(config)
    filename = "erase-" + str(UUID(request_id)) + ".json"
    path = base / filename
    if not path.exists():
        path = base / "deferred-erasure" / filename
    if not path.exists():
        return
    value = json.loads(path.read_text())
    if value.get("phase") == "failed":
        return
    state = getattr(error, "sqlstate", None)
    reason = (
        error
        if isinstance(error, str) and error in ERASURE_FAILURES
        else {
            "25P04": "CRITICAL_DEADLINE",
            "57014": "DATABASE_CANCELLED",
            "55P03": "RESOURCE_BUSY",
            "40001": "VERSION_CONFLICT",
            "23503": "DEPENDENCY_CONFLICT",
            "42501": "AUTHORIZATION_REVOKED",
            "08006": "CONNECTION_OR_FILESYSTEM",
        }.get(str(state), "UNEXPECTED_FAILURE")
    )
    if isinstance(error, RuntimeError):
        reason = {
            "managed_backup_erasure_failed": "BACKUP_ERASURE_FAILED",
            "executor_cleanup_pending": "WORKER_CLEANUP_FAILED",
        }.get(str(error), reason)
    if isinstance(error, OSError) or (
        isinstance(error, psycopg.OperationalError) and state is None
    ):
        reason = "CONNECTION_OR_FILESYSTEM"
    record = {
        "event": "server_erasure_aborted",
        "service": "automation-control",
        "request_id": str(UUID(request_id)),
        "server_id": value.get("server_id"),
        "actor_id": value.get("actor_id"),
        "aborted_at": datetime.now(UTC).isoformat(),
        "error_code": reason,
        "error_type": type(error).__name__ if isinstance(error, Exception) else None,
        "database_error_code": state,
        "previous_phase": value.get("phase"),
        "reason": ERASURE_FAILURES[reason],
        "automatic_retry": False,
    }
    value.update(record, phase="failed", previous_phase=value.get("phase"))
    value.pop("next_attempt_at", None)
    value.pop("retry_count", None)
    line = json.dumps(record, ensure_ascii=False) + "\n"
    logging.getLogger("cve.erasure").error(line.rstrip())
    atomic(path, value)
    descriptor = os.open(base / "erasure.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a") as log:
        log.write(line)
        log.flush()
        os.fsync(log.fileno())


def abort_unfinished_erasures(config: Config) -> None:
    base = directory(config)
    for pattern in ("erase-*.json", "deferred-erasure/erase-*.json"):
        for path in base.glob(pattern):
            fail_erasure(config, path.stem.removeprefix("erase-"), "INTERRUPTED")


def process_restart(config: Config) -> None:
    """Execute only a committed n8n authorization, outside every application container."""
    from cve_common.deployment import GROUPS, RESTART_TARGETS

    from scripts.application.manage import identity

    with shared_operation(config):
        with db.connect(config, "dashboard_admin") as session:
            row = session.execute("SELECT status.claim_restart() AS value").fetchone()
        if not row or not row["value"]:
            return
        request = row["value"]
        result: dict[str, Any] = {"ok": False, "error_code": "RESTART_FAILED"}
        try:
            role = RESTART_TARGETS[request["service_id"]]
            group = next(name for name, roles in GROUPS.items() if role in roles)
            container = identity(config, group)
            output = run(
                [
                    *docker_command(),
                    "exec",
                    container["Id"],
                    "python",
                    "-c",
                    "import json,os,sys;from cve_common.application import request_restart;"
                    "print(json.dumps(request_restart(os.environ['CVE_APPLICATION_PROFILE'],"
                    "sys.argv[1],sys.argv[2])))",
                    role,
                    str(UUID(request["id"])),
                ]
            )
            result = json.loads(output.stdout)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            pass
        with db.connect(config, "dashboard_admin") as session:
            session.execute(
                "SELECT status.finish_restart(%s,%s,%s,%s,%s,%s)",
                (
                    request["id"],
                    request["lease_token"],
                    bool(result.get("ok")),
                    result.get("error_code") or (None if result.get("ok") else "RESTART_FAILED"),
                    result.get("old_pid"),
                    result.get("new_pid"),
                ),
            )


async def serve(config: Config) -> None:
    prepare(config)
    abort_unfinished_erasures(config)
    service = config.secrets_base / "services" / config.project
    socket_path = service / "control.sock"
    socket_path.unlink(missing_ok=True)

    async def client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await asyncio.wait_for(reader.readline(), 5)
            if len(raw) > 8192:
                raise ValueError("request_limit")
            message = json.loads(raw)
            signature = message.pop("signature", "")
            canonical = json.dumps(message, sort_keys=True, separators=(",", ":")).encode()
            expected = hmac.new(
                (service / "control.token").read_bytes(), canonical, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("unauthorized")
            if message.get("operation") == "health":
                result = {"status": 200}
            elif message.get("operation") == "erase":
                result = await asyncio.to_thread(erase, config, message)
            elif message.get("operation") == "erase-status":
                result = await asyncio.to_thread(erasure_status, config, message)
            else:
                raise ValueError("operation_denied")
        except Exception:
            result = {"status": 503}
        writer.write((json.dumps(result) + "\n").encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_unix_server(client, path=socket_path, limit=8192)
    socket_path.chmod(0o600)

    async def recover() -> None:
        while True:
            with contextlib.suppress(Exception):
                from scripts.smtp.manage import process as process_smtp

                await asyncio.to_thread(process_smtp, config)
            with contextlib.suppress(Exception):
                from scripts.smtp.testing import process as process_smtp_test

                await asyncio.to_thread(process_smtp_test, config)
            try:
                from scripts.automation_executor.network import install_guard

                await asyncio.to_thread(install_guard, config)
            except Exception:
                pass
            await asyncio.sleep(5)

    async def restart_jobs() -> None:
        while True:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(process_restart, config)
            await asyncio.sleep(1)

    from cve_common.deployment import RESTART_TARGETS

    async def observe_services() -> None:
        from scripts.automation_executor.watchdog import observe

        while True:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(observe, config)
            await asyncio.sleep(30)

    observer_task = asyncio.create_task(observe_services())

    async def refresh_tls() -> None:
        from scripts.infrastructure.tls import refresh

        while True:
            await asyncio.sleep(60)
            try:
                await asyncio.to_thread(refresh, config)
            except Exception:
                print(
                    "TLS-Aktualisierung fehlgeschlagen; bisheriges Zertifikat bleibt aktiv.",
                    file=sys.stderr,
                    flush=True,
                )

    tls_task = asyncio.create_task(refresh_tls())
    restart_tasks = [asyncio.create_task(restart_jobs()) for _ in RESTART_TARGETS]
    task = asyncio.create_task(recover())
    try:
        async with server:
            await server.serve_forever()
    finally:
        task.cancel()
        observer_task.cancel()
        tls_task.cancel()
        for restart_task in restart_tasks:
            restart_task.cancel()
        await asyncio.gather(task, observer_task, tls_task, *restart_tasks, return_exceptions=True)
        socket_path.unlink(missing_ok=True)


def start(config: Config) -> None:
    prepare(config)
    base = directory(config)
    service = config.secrets_base / "services" / config.project
    unit = "cve-automation-control-" + config.project
    if (
        shutil.which("systemctl")
        and subprocess.run(
            ["systemctl", "--user", "is-active", "--quiet", unit],
            capture_output=True,
            check=False,
        ).returncode
        == 0
    ):
        # Reload the controller code/configuration without starting a duplicate socket owner.
        (service / "control.sock").unlink(missing_ok=True)
        subprocess.run(["systemctl", "--user", "restart", unit], check=True, capture_output=True)
        for _ in range(100):
            if (service / "control.sock").exists():
                return
            time.sleep(0.1)
        raise RuntimeError("Restarted host control agent did not become ready")
    pid = base / "agent.pid"
    if pid.exists():
        try:
            os.kill(int(pid.read_text()), 0)
            if (service / "control.sock").exists():
                return
        except (OSError, ValueError):
            pass
    # Supervise the host control process when the user's service manager is available.
    available = (
        shutil.which("systemd-run")
        and subprocess.run(
            ["systemctl", "--user", "show-environment"], capture_output=True, check=False
        ).returncode
        == 0
    )
    if available:
        unit = "cve-automation-control-" + config.project
        result = subprocess.run(
            [
                "systemd-run",
                "--user",
                "--unit=" + unit,
                "--collect",
                "--property=Restart=on-failure",
                "--property=RestartSec=2",
                "--property=WorkingDirectory=" + str(config.root),
                "--property=UMask=0077",
                "--setenv=CVE_DOCKER_SUDO=" + os.environ.get("CVE_DOCKER_SUDO", ""),
                sys.executable,
                "-m",
                "scripts.automation_executor.agent",
                "--config",
                str(base / "agent-config.json"),
            ],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            for _ in range(100):
                if (service / "control.sock").exists():
                    return
                time.sleep(0.1)
            raise RuntimeError("Supervised host control agent did not start")
    log = (base / "agent.log").open("ab")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "scripts.automation_executor.agent",
            "--config",
            str(base / "agent-config.json"),
        ],
        cwd=config.root,
        env={**os.environ, "CVE_DOCKER_SUDO": os.environ.get("CVE_DOCKER_SUDO", "")},
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        start_new_session=True,
    )
    pid.write_text(str(process.pid))
    pid.chmod(0o600)
    for _ in range(100):
        if (service / "control.sock").exists():
            return
        if process.poll() is not None:
            break
        time.sleep(0.1)
    raise RuntimeError("Host control agent did not start")


def stop(config: Config) -> None:
    """Stop only this project's host controller, never an unrelated PID or user unit."""
    unit = "cve-automation-control-" + config.project
    if shutil.which("systemctl"):
        active = subprocess.run(
            ["systemctl", "--user", "is-active", "--quiet", unit], capture_output=True, check=False
        )
        if active.returncode == 0:
            working = run(
                ["systemctl", "--user", "show", "--property=WorkingDirectory", "--value", unit]
            ).stdout.strip()
            if working != str(config.root):
                raise ValueError("Hostcontroller gehört zu einem anderen Arbeitsverzeichnis.")
            run(["systemctl", "--user", "stop", unit])
    pidfile = directory(config) / "agent.pid"
    if not pidfile.exists():
        return
    pid = int(pidfile.read_text())
    commandline = Path("/proc") / str(pid) / "cmdline"
    if commandline.exists():
        args = commandline.read_bytes().decode().split("\0")
        expected = str(directory(config) / "agent-config.json")
        if pid <= 1 or args[1:5] != [
            "-m",
            "scripts.automation_executor.agent",
            "--config",
            expected,
        ]:
            raise ValueError("Controller-PID konnte diesem Projekt nicht sicher zugeordnet werden.")
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 15
        while commandline.exists() and commandline.read_bytes():
            if time.monotonic() >= deadline:
                raise ValueError("Hostcontroller wurde nicht rechtzeitig beendet.")
            time.sleep(0.1)
    pidfile.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    value = json.loads(args.config.read_text())
    config = Config(Path(value["root"]), value["values"])
    asyncio.run(serve(config))


if __name__ == "__main__":
    main()
