"""Supervise application profiles, fail closed until host network guards are installed."""

import json
import os
import select
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from uuid import UUID, uuid4

from cve_common.deployment import GROUPS, PORTS

MODULES = {
    "cve-api": "cve_api",
    "cve-event-dispatcher": "cve_event_dispatcher",
    "cve-inventory": "cve_inventory",
    "cve-matcher": "cve_matcher",
    "cve-findings": "cve_findings",
    "cve-notification": "cve_notification",
    "cve-importer": "cve_importer",
    "cve-enricher": "cve_enricher",
    "cve-automation": "cve_automation",
}
STATE = Path("/tmp/cve-application-state.json")
BOOT = Path("/tmp/cve-application-boot.json")


CONTROL = Path("/tmp/cve-application-control.sock")
RECEIPTS = Path("/tmp/cve-application-restarts")


def role_ready(role: str) -> bool:
    path = "/health/worker" if role == "cve-notification" else "/health/ready"
    protocol = "https" if role == "cve-notification" else "http"
    context = (
        ssl.create_default_context(cafile="/run/cve-notification/ca.crt")
        if protocol == "https"
        else None
    )
    hostname = "localhost" if protocol == "https" else "127.0.0.1"
    try:
        with urllib.request.urlopen(
            f"{protocol}://{hostname}:{PORTS[role]}{path}", context=context, timeout=2
        ) as response:
            return bool(response.status == 200)
    except (OSError, ValueError):
        return False


def request_restart(profile: str, role: str, request_id: str) -> dict[str, object]:
    if role not in GROUPS["cve-" + profile]:
        raise ValueError("restart_target_denied")
    identity = str(UUID(request_id))
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(90)
        client.connect(str(CONTROL))
        client.sendall(json.dumps({"role": role, "id": identity}).encode() + b"\n")
        with client.makefile("rb") as stream:
            value: dict[str, object] = json.loads(stream.readline(4096))
        return value


def check(profile: str) -> bool:
    if profile != "api":
        try:
            state = json.loads(STATE.read_text())
            if state["profile"] != profile or set(state["children"]) != set(
                GROUPS["cve-" + profile]
            ):
                return False
            for pid in state["children"].values():
                os.kill(int(pid), 0)
        except (OSError, ValueError, KeyError, TypeError):
            return False
    return all(role_ready(role) for role in GROUPS["cve-" + profile])


def supervise(profile: str) -> int:
    stopping = False

    def stop(_signal: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    identity = os.readlink("/proc/self/ns/net") + " " + str(uuid4())
    BOOT.write_text(json.dumps({"profile": profile, "identity": identity}))
    BOOT.chmod(0o600)
    ready = Path("/run/cve-application") / (profile + ".ready")
    while not stopping and profile != "api":
        if ready.is_file() and ready.read_text().strip() == identity:
            break
        time.sleep(0.1)
    if stopping:
        return 0
    children: dict[str, subprocess.Popen[bytes]] = {}
    state_lock = threading.RLock()
    role_locks = {role: threading.Lock() for role in GROUPS["cve-" + profile]}
    restarters = ThreadPoolExecutor(max_workers=len(role_locks))
    code = 0
    CONTROL.unlink(missing_ok=True)
    RECEIPTS.mkdir(mode=0o700, exist_ok=True)
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(CONTROL))
    CONTROL.chmod(0o600)
    server.listen(8)

    def save_state() -> None:
        with state_lock:
            temporary = STATE.with_suffix(".pending")
            temporary.write_text(
                json.dumps(
                    {"profile": profile, "children": {r: p.pid for r, p in children.items()}}
                )
            )
            temporary.chmod(0o600)
            temporary.replace(STATE)

    def restart_owned(message: dict[str, str]) -> dict[str, object]:
        role, identity = message["role"], str(UUID(message["id"]))
        if role not in children:
            raise ValueError("restart_target_denied")
        receipt = RECEIPTS / (identity + ".json")
        if receipt.exists():
            value: dict[str, object] = json.loads(receipt.read_text())
            if value["role"] != role:
                raise ValueError("restart_identity_conflict")
            return value
        old = children[role]
        if old.poll() is None:
            old.terminate()
            with suppress(subprocess.TimeoutExpired):
                old.wait(timeout=30)
            with suppress(ProcessLookupError):
                os.killpg(old.pid, signal.SIGKILL)
            old.wait(timeout=2)
        with state_lock:
            if stopping:
                raise ValueError("supervisor_stopping")
            children[role] = subprocess.Popen(
                [sys.executable, "-m", MODULES[role] + ".main"], start_new_session=True
            )
            save_state()
        deadline = time.monotonic() + 30
        success = False
        while time.monotonic() < deadline and not stopping:
            if children[role].poll() is not None:
                break
            if role_ready(role):
                success = True
                break
            time.sleep(0.2)
        value = {
            "role": role,
            "old_pid": old.pid,
            "new_pid": children[role].pid,
            "ok": success,
            "error_code": None if success else "SERVICE_NOT_READY",
        }
        temporary = receipt.with_suffix(".pending")
        temporary.write_text(json.dumps(value))
        temporary.chmod(0o600)
        temporary.replace(receipt)
        return value

    def serve_restart(connection: socket.socket) -> None:
        with connection:
            connection.settimeout(2)
            owned = None
            try:
                with connection.makefile("rb") as stream:
                    raw = stream.readline(1025)
                if len(raw) > 1024:
                    raise ValueError("request_limit")
                message = json.loads(raw)
                owned = role_locks.get(message["role"])
                if owned is None or not owned.acquire(blocking=False):
                    owned = None
                    raise ValueError("restart_target_busy_or_denied")
                result = restart_owned(message)
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                AttributeError,
                subprocess.SubprocessError,
            ):
                result = {"ok": False, "error_code": "RESTART_FAILED"}
            finally:
                if owned is not None:
                    owned.release()
            with suppress(OSError):
                connection.sendall(json.dumps(result).encode() + b"\n")

    try:
        for role in GROUPS["cve-" + profile]:
            children[role] = subprocess.Popen(
                [sys.executable, "-m", MODULES[role] + ".main"], start_new_session=True
            )
        save_state()
        while not stopping:
            # Reap a failed child but keep its peers and the container alive.
            # The authorized process-restart command can recover the failed service.
            for child in children.values():
                child.poll()
            if select.select([server], [], [], 0.2)[0]:
                connection, _ = server.accept()
                restarters.submit(serve_restart, connection)
    finally:
        server.close()
        restarters.shutdown(wait=True, cancel_futures=True)
        CONTROL.unlink(missing_ok=True)
        STATE.unlink(missing_ok=True)
        for child in children.values():
            if child.poll() is None:
                with suppress(ProcessLookupError):
                    # Let each service drain/cancel its jobs before it stops parser children.
                    child.terminate()
        deadline = time.monotonic() + 10
        for child in children.values():
            try:
                child.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=2)
    return code


def main() -> None:
    profile = os.environ.get("CVE_APPLICATION_PROFILE", "")
    if profile not in {"api", "processing", "sources"}:
        raise SystemExit("Explicit application profile required")
    if sys.argv[1:] == ["health"]:
        raise SystemExit(0 if check(profile) else 1)
    if len(sys.argv) == 4 and sys.argv[1] == "restart":
        print(json.dumps(request_restart(profile, sys.argv[2], sys.argv[3])))
        return
    if sys.argv[1:]:
        raise SystemExit("Unknown application command")
    raise SystemExit(supervise(profile))


if __name__ == "__main__":
    main()
