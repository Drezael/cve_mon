"""Project-scoped container inspection and host network-namespace tools; no proxy service."""

import json
import os
import subprocess
import time
from typing import Any

from scripts.infrastructure.manage import Config, compose, docker_command, run


def inspect_container(name: str) -> dict[str, Any]:
    return dict(json.loads(run([*docker_command(), "inspect", name]).stdout)[0])


def namespace_command(pid: int, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    "Hostwerkzeug ausschließlich im expliziten Container-Netznamespace; kein Mount-/PID-Wechsel."
    prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
    return run([*prefix, "nsenter", "--target", str(pid), "--net", "--", *args], **kwargs)


def wait_client_ready(config: Config, service: str, timeout: float = 60) -> None:
    """Wait for fresh health probes after guard release, including a cached unhealthy state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        identifier = compose(config, ["ps", "-q", service]).stdout.strip()
        if identifier:
            state = inspect_container(identifier)["State"]
            if state.get("Running") and state.get("Health", {}).get("Status") == "healthy":
                return
        time.sleep(0.5)
    raise ValueError("Bounded client readiness deadline exceeded")
