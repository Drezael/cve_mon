"""Effektive Docker-/Kernelgrenzen, auch beim Umgehen der Proxyvariablen."""

import pytest

from scripts.infrastructure.envoy import inspect_container, namespace_command, netns
from scripts.infrastructure.manage import docker_command, run
from tests.infrastructure.envoy.conftest import Lab

pytestmark = [pytest.mark.egress, pytest.mark.security]


def test_container_hardening_and_networks(envoy_lab: Lab) -> None:
    name, pid = netns(envoy_lab.config)
    item = inspect_container(name)
    assert set(item["NetworkSettings"]["Networks"]) == {
        envoy_lab.config.project + "_cve_egress_internal",
        envoy_lab.config.project + "_cve_egress_external",
    }
    assert not item["HostConfig"]["PortBindings"]
    assert not item["HostConfig"]["Privileged"] and item["HostConfig"]["ReadonlyRootfs"]
    assert item["Config"]["User"] == "65532:65532"
    status = run([*docker_command(), "exec", name, "cat", "/proc/1/status"]).stdout
    assert "CapEff:\t0000000000000000" in status
    assert "Uid:\t65532\t65532\t65532\t65532" in status
    rules = namespace_command(pid, ["nft", "list", "table", "inet", "cve_egress"]).stdout
    assert "policy drop" in rules and "meta nfproto ipv6" in rules


@pytest.mark.parametrize(
    "target,port",
    [
        ("93.184.216.34", 80),
        ("93.184.216.34", 443),
        ("93.184.216.34", 587),
        ("1.1.1.1", 443),
        ("169.254.169.254", 80),
        ("::1", 443),
        ("::ffff:127.0.0.1", 80),
    ],
)
def test_clients_cannot_connect_directly(envoy_lab: Lab, target: str, port: int) -> None:
    assert "error" in envoy_lab.request(kind="direct", target=target, target_port=port)


def test_host_gateway_and_other_docker_network_not_accessible(envoy_lab: Lab) -> None:
    networks = inspect_container(envoy_lab.sink)["NetworkSettings"]["Networks"]
    external = next(iter(networks.values()))
    for target in (external["IPAddress"], external["Gateway"]):
        for port in (80, 443, 587, 3128, 5432):
            assert "error" in envoy_lab.request(kind="direct", target=target, target_port=port)


def test_namespace_rules_are_not_installed_in_host(envoy_lab: Lab) -> None:
    prefix = []
    import os

    if os.geteuid() != 0:
        prefix = ["sudo", "-n"]
    host = run([*prefix, "nft", "list", "tables"]).stdout
    assert "table inet cve_egress" not in host
    assert "table inet cve_clientegress" not in host
