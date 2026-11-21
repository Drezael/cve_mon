"""Prepare and start three application groups with namespace-bound startup gates."""

import ipaddress
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from cve_common.deployment import APPLICATION_IMAGE

from scripts.infrastructure.manage import Config, compose, docker_command, run, service_image


def directory(config: Config) -> Path:
    return config.root / ".runtime/application" / config.project


def prepare(config: Config, group: str) -> None:
    from scripts.automation import manage as dispatcher
    from scripts.automation_executor import manage as executor
    from scripts.cve_enricher import manage as enricher
    from scripts.cve_findings import manage as findings
    from scripts.cve_importer import manage as importer
    from scripts.cve_matcher import manage as matcher
    from scripts.inventory_processor import manage as inventory
    from scripts.notifications import manage as notification

    modules = {
        "cve-processing": [
            dispatcher,
            inventory,
            matcher,
            findings,
            notification,
            importer,
            enricher,
        ],
        "cve-sources": [executor],
    }
    for module in modules[group]:
        module.prepare(config)
    if group == "cve-processing":
        api_files = config.secrets_base / "services" / config.project
        if api_files.is_dir():
            from scripts.status.manage import prepare as prepare_status

            prepare_status(config, api_files)
    path = directory(config)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("Private application gate directory required")


def identity(config: Config, group: str) -> dict[str, Any]:
    from scripts.infrastructure.network import inspect_container

    container = compose(config, ["ps", "-q", group], managed=False).stdout.strip()
    if not container:
        raise ValueError("Application group is not running: " + group)
    item = inspect_container(container)
    if (
        item["Config"]["Labels"].get("com.docker.compose.project") != config.project
        or item["Config"]["Labels"].get("com.docker.compose.service") != group
        or item["Config"]["Image"] != service_image(config, group, APPLICATION_IMAGE)
        or not item["State"]["Running"]
        or item["State"]["Pid"] <= 1
    ):
        raise ValueError("Only the running, pinned application group may be released")
    host = item["HostConfig"]
    zones = {
        config.project + "_cve_data",
        config.project + ("_cve_ssh" if group == "cve-sources" else "_cve_internal"),
    }
    if group == "cve-processing":
        zones.add(config.project + "_cve_outbound")
    if (
        host.get("Privileged")
        or host.get("CapAdd")
        or set(host.get("CapDrop", [])) != {"ALL"}
        or not host.get("ReadonlyRootfs")
        or item["Config"].get("User", "0").split(":")[0] in {"0", "root"}
        or set(item["NetworkSettings"]["Networks"]) != zones
    ):
        raise ValueError("Application guards require the unprivileged private network namespace")
    return item


def peer(config: Config, service: str, zone: str) -> str | None:
    from scripts.infrastructure.network import inspect_container
    from scripts.infrastructure.topology import physical

    if service == "cve-mailhog":
        container = run(
            [
                *docker_command(),
                "ps",
                "-q",
                "--filter",
                "label=com.docker.compose.project=" + config.project,
                "--filter",
                "label=com.docker.compose.service=cve-mailhog",
            ]
        ).stdout.strip()
    else:
        container = compose(config, ["ps", "-q", service], managed=False).stdout.strip()
    if not container:
        return None
    item = inspect_container(container)
    if item["Config"]["Labels"].get("com.docker.compose.project") != config.project or item[
        "Config"
    ]["Labels"].get("com.docker.compose.service") != physical(service):
        raise ValueError("Foreign peer endpoint")
    endpoint = item["NetworkSettings"]["Networks"].get(config.project + "_" + zone)
    return str(ipaddress.IPv4Address(endpoint["IPAddress"])) if endpoint else None


def target_peer(config: Config, host: str, zone: str) -> str | None:
    """Configured HTTPS callbacks may only reach an endpoint on this project's private bridge."""
    from cve_common.deployment import SERVICES

    from scripts.infrastructure import network as net
    from scripts.infrastructure.topology import physical

    if physical(host) in SERVICES:
        return peer(config, host, zone)
    network = config.project + "_" + zone
    value = json.loads(run([*docker_command(), "network", "inspect", network]).stdout)[0]
    for container_id in value.get("Containers", {}):
        item = net.inspect_container(container_id)
        endpoint = item["NetworkSettings"]["Networks"].get(network, {})
        if host in endpoint.get("Aliases", []):
            return str(ipaddress.IPv4Address(endpoint["IPAddress"]))
    return None


def processing_guard(config: Config) -> None:
    from scripts.database import manage as db
    from scripts.infrastructure import network as net

    item = identity(config, "cve-processing")
    pid = int(item["State"]["Pid"])
    ns = net.namespace_command(pid, ["readlink", "/proc/self/ns/net"]).stdout.strip()
    if ns == os.readlink("/proc/self/ns/net"):
        raise ValueError("Host namespace forbidden")
    allowed = {(db.address(config), 5432)}
    inputs: set[tuple[str, int]] = set()
    for zone in ["cve_data", "cve_internal", "cve_outbound"]:
        api = peer(config, "cve-api", zone)
        if api:
            inputs.update((api, port) for port in range(8000, 8007))
        for target, port in [("cve-n8n", 5678), ("cve-mail-relay", 2525)]:
            address = peer(config, target, zone)
            if address:
                allowed.add((address, port))
                for local in (
                    [8000]
                    if target == "cve-n8n"
                    else ([8000, 8001, 8002, 8003, 8004] if target == "cve-api" else [])
                ):
                    inputs.add((address, local))
        endpoint = item["NetworkSettings"]["Networks"].get(config.project + "_" + zone)
        if endpoint:
            for port in range(8000, 8007):
                allowed.add((str(ipaddress.IPv4Address(endpoint["IPAddress"])), port))
    # Dispatcher origins are private, validated internal HTTPS destinations.
    from urllib.parse import urlsplit

    from cve_event_dispatcher.dispatcher import load_targets

    targets = config.secrets_base / "automation" / config.project / "targets.json"
    for callback_target in load_targets(targets):
        callback_url = urlsplit(callback_target.origin)
        for zone in ["cve_data", "cve_internal", "cve_outbound"]:
            destination = target_peer(config, str(callback_url.hostname), zone)
            if destination:
                allowed.add((destination, callback_url.port or 443))
    rules = (
        "table inet cve_processing {\n"
        " chain forward { type filter hook forward priority 0; policy drop; }\n"
        " chain output { type filter hook output priority -110; policy drop;\n"
        " ct direction reply accept\n ip daddr 127.0.0.1 accept\n"
        " ip daddr 127.0.0.11 udp dport 53 accept\n ip daddr 127.0.0.11 tcp dport 53 accept\n"
    )
    rules += "".join(
        f" ip daddr {host} tcp dport {port} accept\n" for host, port in sorted(allowed)
    )
    # Direct HTTPS keeps private service bridges and metadata endpoints unreachable.
    rules += (
        " ip daddr { 0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,"
        "127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16,"
        "224.0.0.0/4,240.0.0.0/4 } reject\n"
    )
    rules += " meta nfproto ipv4 tcp dport 443 accept\n"
    rules += (
        " counter reject\n }\n chain input { type filter hook input priority -110; policy drop;\n"
        ' ct state established,related accept\n iifname "lo" accept\n'
    )
    rules += "".join(f" ip saddr {host} tcp dport {port} accept\n" for host, port in sorted(inputs))
    rules += " }\n}\n"
    if "table inet cve_processing" in net.namespace_command(pid, ["nft", "list", "tables"]).stdout:
        rules = "delete table inet cve_processing\n" + rules
    net.namespace_command(pid, ["nft", "-c", "-f", "-"], input=rules)
    net.namespace_command(pid, ["nft", "-f", "-"], input=rules)
    for name in ["cve-matcher", "cve-findings", "notifications"]:
        path = config.secrets_base / name / config.project
        (path / "guard.ready").write_text(ns + "\n")
        (path / "guard.ready").chmod(0o600)
        (path / "guard.nft").write_text(rules)


def sources_guard(config: Config) -> None:
    """Publish this processing namespace's direct-network guard proof."""
    from scripts.infrastructure import network as net

    item = identity(config, "cve-processing")
    processing_guard(config)
    ns = net.namespace_command(
        int(item["State"]["Pid"]), ["readlink", "/proc/self/ns/net"]
    ).stdout.strip()
    for name in ["cve-importer", "cve-enricher"]:
        path = config.secrets_base / name / config.project / "egress.ready"
        path.write_text(ns + "\n")
        path.chmod(0o600)


def release(config: Config, group: str) -> None:
    from scripts.infrastructure import network as net

    item = identity(config, group)
    result = run([*docker_command(), "exec", item["Id"], "cat", "/tmp/cve-application-boot.json"])
    boot = json.loads(result.stdout)
    ns = net.namespace_command(
        int(item["State"]["Pid"]), ["readlink", "/proc/self/ns/net"]
    ).stdout.strip()
    if boot["profile"] != group.removeprefix("cve-") or not boot["identity"].startswith(ns + " "):
        raise ValueError("Fresh namespace-bound application boot proof required")
    target = directory(config) / (boot["profile"] + ".ready")
    temporary = target.with_suffix(".pending")
    temporary.write_text(boot["identity"] + "\n")
    temporary.chmod(0o600)
    temporary.replace(target)


def start(config: Config, group: str, *, force: bool = False) -> None:
    if group not in {"cve-processing", "cve-sources"}:
        raise ValueError("Worker group required")
    if not config.compose_overrides:
        from scripts.application.build import build

        build(config)
    prepare(config, group)
    args = ["up", "-d", "--no-deps", *(["--force-recreate"] if force else []), group]
    compose(config, args, managed=False)
    for _ in range(100):
        item = identity(config, group)
        result = subprocess.run(
            [*docker_command(), "exec", item["Id"], "test", "-f", "/tmp/cve-application-boot.json"],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            break
        time.sleep(0.1)
    else:
        raise ValueError("Application boot proof deadline exceeded")
    try:
        if group == "cve-processing":
            sources_guard(config)
            processing_guard(config)
        else:
            from scripts.automation_executor.network import install_guard

            install_guard(config)
        release(config, group)
        if group == "cve-sources":
            from scripts.automation_executor.agent import start as start_control

            start_control(config)
    except BaseException:
        compose(config, ["stop", group], managed=False)
        raise


def main() -> int:
    """Compatibility for old callers; the sole CLI implementation is root/cve_mon."""
    import sys

    aliases = {"up": "start", "down": "stop", "check": "health"}
    arguments = sys.argv[1:]
    if arguments:
        arguments[0] = aliases.get(arguments[0], arguments[0])
    return subprocess.call(
        [sys.executable, str(Path(__file__).resolve().parents[2] / "cve_mon"), *arguments]
    )


if __name__ == "__main__":
    raise SystemExit(main())
