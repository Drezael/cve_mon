"""Certbot scheduler without Docker access; Nginx activation belongs to the host controller."""

import json
import os
import random
import signal
import subprocess
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path

STATE = Path("/var/lib/letsencrypt/cve-renewal.json")
CERTIFICATE = Path("/etc/letsencrypt/live/dashboard/fullchain.pem")
STOP = threading.Event()
CURRENT: subprocess.Popen[bytes] | None = None


def arguments(*, dry_run: bool = False) -> list[str]:
    """Use a fixed CA and certificate name; domain and contact are external inputs."""
    command = [
        "certbot",
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--email",
        os.environ["ACME_EMAIL"],
        "--cert-name",
        "dashboard",
        "-d",
        os.environ["ACME_DOMAIN"],
        "--server",
        "https://acme-staging-v02.api.letsencrypt.org/directory"
        if dry_run
        else "https://acme-v02.api.letsencrypt.org/directory",
        "--keep-until-expiring",
    ]
    command += [
        "--dns-cloudflare",
        "--dns-cloudflare-credentials",
        "/run/cve-acme/cloudflare.ini",
        "--dns-cloudflare-propagation-seconds",
        "60",
        "--preferred-challenges",
        "dns-01",
    ]
    if dry_run:
        command.append("--dry-run")
    return command


def cycle() -> bool:
    """Retain the old lineage on failure and retry later, without forced renewal."""
    global CURRENT
    try:
        CURRENT = subprocess.Popen(arguments())
        if STOP.is_set():
            CURRENT.terminate()
        success = CURRENT.wait(timeout=600) == 0 and CERTIFICATE.is_file()
    except subprocess.TimeoutExpired:
        assert CURRENT is not None
        CURRENT.kill()
        CURRENT.wait()
        success = False
    except OSError:
        success = False
    finally:
        CURRENT = None
    temporary = STATE.with_suffix(".new")
    temporary.write_text(json.dumps({"checked_at": time.time(), "ok": success}) + "\n")
    temporary.chmod(0o600)
    temporary.replace(STATE)
    print(
        "ACME: Prüfung erfolgreich."
        if success
        else "ACME: Prüfung fehlgeschlagen; Wiederholung in einer Stunde.",
        flush=True,
    )
    return success


def healthy() -> bool:
    try:
        state = json.loads(STATE.read_text())
        return bool(
            state["ok"]
            and 0 <= time.time() - state["checked_at"] < 14 * 3600
            and CERTIFICATE.is_file()
        )
    except (OSError, ValueError, KeyError, TypeError):
        return False


def stop(signum: int, _frame: object) -> None:
    """Forward shutdown so Certbot can clean its DNS challenge before exiting."""
    STOP.set()
    if CURRENT is not None:
        with suppress(ProcessLookupError):
            CURRENT.send_signal(signum)


def main() -> int:
    if sys.argv[1:] == ["health"]:
        return 0 if healthy() else 1
    if sys.argv[1:] == ["dry-run"]:
        return subprocess.run(arguments(dry_run=True), check=False, timeout=600).returncode
    os.umask(0o077)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    while not STOP.is_set():
        success = cycle()
        STOP.wait(12 * 3600 + random.SystemRandom().randint(0, 3600) if success else 3600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
