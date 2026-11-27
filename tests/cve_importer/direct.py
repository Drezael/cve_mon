"""Controlled public-IP source fixture on the actual processing outbound bridge."""

import json
from dataclasses import replace

from scripts.application.manage import start
from scripts.infrastructure import network as net
from scripts.infrastructure.manage import Config, compose, docker_command, run


def configuration(config: Config, hosts: list[str]) -> Config:
    overlay = config.root / ".runtime" / (config.project + "-source-hosts.json")
    overlay.write_text(
        json.dumps(
            {
                "services": {
                    "cve-processing": {"extra_hosts": {host: "93.184.216.34" for host in hosts}}
                }
            }
        )
    )
    return replace(config, compose_overrides=(*config.compose_overrides, overlay))


def route(config: Config, sink: str) -> None:
    bridge = config.project + "_cve_outbound"
    item = net.inspect_container(sink)
    if bridge not in item["NetworkSettings"]["Networks"]:
        run([*docker_command(), "network", "connect", bridge, sink])
        item = net.inspect_container(sink)
    address = item["NetworkSettings"]["Networks"][bridge]["IPAddress"]
    identity = compose(config, ["ps", "-q", "cve-processing"]).stdout.strip()
    pid = int(net.inspect_container(identity)["State"]["Pid"])
    net.namespace_command(pid, ["ip", "route", "replace", "93.184.216.34/32", "via", address])


def rebind(config: Config, sink: str) -> None:
    start(config, "cve-processing")
    route(config, sink)


def outage(config: Config) -> None:
    identity = compose(config, ["ps", "-q", "cve-processing"]).stdout.strip()
    pid = int(net.inspect_container(identity)["State"]["Pid"])
    net.namespace_command(pid, ["ip", "route", "replace", "blackhole", "93.184.216.34/32"])
