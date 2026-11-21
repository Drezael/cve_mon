"""Observe fixed own-project endpoints; only n8n may decide on process recovery."""

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from cve_common.deployment import GROUPS, PORTS, RESTART_TARGETS, VENDORS

from scripts.database import manage as db
from scripts.infrastructure.manage import Config, docker_command

# Run in the existing application interpreter, independently of all worker event loops.
# No service name, URL, path or command is supplied by a user or by n8n.
PROBE = """
import concurrent.futures,json,ssl,urllib.request,sys
ports=json.loads(sys.argv[1])
def probe(item):
 role,port=item
 protocol='https' if role=='cve-notification' else 'http'
 hostname='localhost' if protocol=='https' else '127.0.0.1'
 context=None
 if protocol=='https':
  context=ssl.create_default_context(cafile='/run/cve-notification/ca.crt')
 try:
  url=f'{protocol}://{hostname}:{port}/health/live'
  with urllib.request.urlopen(url,context=context,timeout=3) as r:
   return role,r.status==200
 except (OSError,ValueError):
  return role,False
with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as pool:
 print(json.dumps(dict(pool.map(probe,ports.items()))))
"""


def command(args: list[str]) -> str:
    return subprocess.run(
        [*docker_command(), *args], check=True, capture_output=True, text=True, timeout=12
    ).stdout


def probe_group(container: dict[str, Any], group: str) -> dict[str, bool] | None:
    """An unavailable supervisor/container is reported, never restarted by this observer."""
    if not container["State"]["Running"] or container["State"].get("Paused"):
        return None
    ports = {role: PORTS[role] for role in GROUPS[group]}
    try:
        result: dict[str, bool] = json.loads(
            command(["exec", container["Id"], "python", "-c", PROBE, json.dumps(ports)])
        )
        if set(result) != set(ports) or any(type(v) is not bool for v in result.values()):
            return None
        return result
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def observe(config: Config) -> None:
    """One independent, bounded sweep; observations and streaks survive controller restarts."""
    ids = command(
        ["ps", "-aq", "--filter", "label=com.docker.compose.project=" + config.project]
    ).split()
    if not ids:
        return
    containers = json.loads(command(["inspect", *ids]))
    owned = {
        c["Config"]["Labels"].get("com.docker.compose.service"): c
        for c in containers
        if c["Config"]["Labels"].get("com.docker.compose.project") == config.project
    }
    observations: list[tuple[str, bool, bool, str]] = []
    with ThreadPoolExecutor(max_workers=len(GROUPS)) as executor:
        checks = {
            group: executor.submit(probe_group, owned[group], group)
            for group in GROUPS
            if group in owned
        }
        for group, roles in GROUPS.items():
            result = checks[group].result() if group in checks else None
            for role in roles:
                service = next(k for k, v in RESTART_TARGETS.items() if v == role)
                responsive = result is not None and result[role]
                code = (
                    "OK"
                    if responsive
                    else ("CONTAINER_UNAVAILABLE" if result is None else "UNRESPONSIVE")
                )
                observations.append((service, responsive, True, code))
    for service in VENDORS:
        state = owned.get(service, {}).get("State", {})
        responsive = bool(
            state.get("Running")
            and not state.get("Paused")
            and state.get("Health", {}).get("Status") == "healthy"
        )
        observations.append(
            (service, responsive, False, "OK" if responsive else "VENDOR_UNHEALTHY")
        )
    with db.connect(config, "dashboard_admin") as session:
        for observation in observations:
            session.execute("SELECT status.watchdog_observe(%s,%s,%s,%s)", observation)
