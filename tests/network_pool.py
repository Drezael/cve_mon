"""Opt-in compact subnets for disposable QA labs on shared Docker daemons."""

import hashlib
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts.infrastructure import manage

SYSTEM_RUN = subprocess.run

PREFIXES = (
    "cve-db-test-",
    "cve-test-",
    "cve-mail-test-",
    "cve-egress-test-",
    "cve-db-restore-",
    "cve-n8n-bootstrap-test-",
)
ZONES = (
    "cve_ingress",
    "cve_internal",
    "cve_data",
    "cve_outbound",
    "cve_ssh",
    "cve_egress_internal",
    "cve_egress_external",
)
RESERVED: dict[str, str] = {}
ACTIVE = False


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: Any) -> None:
    global ACTIVE
    markers = {
        "orchestration",
        "deployment",
        "hardening",
        "status_integration",
        "dashboard_administration",
        "dashboard",
        "infrastructure",
        "database",
        "egress",
        "mail",
        "services_integration",
        "automation",
        "authentication",
        "authorization",
        "server_administration",
        "inventory_upload",
        "inventory_processor",
        "cve_importer",
        "cve_enricher",
        "matching",
        "findings",
        "notifications",
    }
    ACTIVE = any(mark.name in markers for mark in item.iter_markers())


def subnet(name: str) -> str:
    if name in RESERVED:
        return RESERVED[name]
    command = manage.docker_command()
    ids = SYSTEM_RUN(
        [*command, "network", "ls", "-q"], check=True, capture_output=True, text=True
    ).stdout.split()
    if ids:
        inspected = SYSTEM_RUN(
            [*command, "network", "inspect", *ids], capture_output=True, text=True
        )
        # Another disposable lab may finish between listing and inspecting.
        if inspected.returncode and not all(
            re.fullmatch(r"Error response from daemon: network \S+ not found", line)
            for line in inspected.stderr.splitlines()
        ):
            inspected.check_returncode()
        networks = json.loads(inspected.stdout)
    else:
        networks = []
    used = [
        ipaddress.ip_network(value["Subnet"])
        for entry in networks
        for value in entry.get("IPAM", {}).get("Config") or []
        if "Subnet" in value
    ]
    for entry in networks:
        if entry["Name"] == name:
            return str(
                next(value["Subnet"] for value in entry["IPAM"]["Config"] if "Subnet" in value)
            )
    routes = json.loads(
        SYSTEM_RUN(
            ["ip", "-j", "-4", "route", "show", "table", "all"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    used.extend(
        ipaddress.ip_network(entry["dst"], strict=False)
        for entry in routes
        if entry.get("dst", "default") != "default"
    )
    used.extend(ipaddress.ip_network(value) for value in RESERVED.values())
    pool = ipaddress.ip_network(os.environ.get("CVE_TEST_NETWORK_POOL", "10.240.0.0/12"))
    private = [
        ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    ]
    if (
        pool.version != 4
        or pool.prefixlen > 24
        or not any(pool.subnet_of(block) for block in private)
    ):
        raise ValueError("QA network pool must be a private IPv4 range of /24 or larger")
    count = 1 << (28 - pool.prefixlen)
    offset = int.from_bytes(hashlib.sha256(name.encode()).digest()[:4]) % count
    for step in range(count):
        candidate = ipaddress.ip_network(
            (int(pool.network_address) + ((offset + step) % count) * 16, 28)
        )
        if not any(candidate.overlaps(existing) for existing in used if existing.version == 4):
            RESERVED[name] = str(candidate)
            return str(candidate)
    raise ValueError("No non-overlapping compact QA subnet available; choose CVE_TEST_NETWORK_POOL")


def overlay(root: Path, project: str) -> Path:
    folder = root / ".runtime/test-policy" / project
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = folder / "networks.json"
    if not target.exists():
        target.write_text(
            json.dumps(
                {
                    "networks": {
                        zone: {"ipam": {"config": [{"subnet": subnet(project + "_" + zone)}]}}
                        for zone in ZONES
                    }
                }
            )
        )
    return target


def pytest_configure(config: Any) -> None:
    if os.environ.get("CVE_TEST_COMPACT_NETWORKS", "1") != "1":
        return

    def compact_run(*args: Any, **kwargs: Any) -> Any:
        command = args[0] if args else kwargs.get("args")
        if ACTIVE and isinstance(command, list) and all(isinstance(v, str) for v in command):
            docker = next(
                (i for i, value in enumerate(command[:4]) if Path(value).name == "docker"), None
            )
            if docker is not None:
                if (
                    command[docker + 1 : docker + 3] == ["network", "create"]
                    and command[-1].startswith(PREFIXES)
                    and "--subnet" not in command
                ):
                    command = [*command[:-1], "--subnet", subnet(command[-1]), command[-1]]
                elif (
                    command[docker + 1 : docker + 2] == ["compose"]
                    and "--project-name" in command
                    and any(value in command for value in ("up", "create"))
                ):
                    project = command[command.index("--project-name") + 1]
                    files = [i for i, value in enumerate(command) if value == "-f"]
                    if project.startswith(PREFIXES) and files:
                        root = Path(command[files[0] + 1]).parent
                        target = str(overlay(root, project))
                        if target not in command:
                            index = files[-1] + 2
                            command = [*command[:index], "-f", target, *command[index:]]
        if args:
            args = (command, *args[1:])
        else:
            kwargs["args"] = command
        return SYSTEM_RUN(*args, **kwargs)

    # Hook the process boundary so early `from ... import compose/run` references
    # receive the same fixture policy. Only isolated project mutations match above.
    subprocess.run = compact_run
