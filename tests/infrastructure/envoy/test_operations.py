"""Ausfall, Ressourcengrenzen, Logs und kontrollierter Neustart ohne offene Übergangsphase."""

import json
import time

import pytest

from scripts.infrastructure.envoy import (
    CLIENT_SERVICES,
    inspect_container,
    namespace_command,
    netns,
    start,
)
from scripts.infrastructure.manage import compose, docker_command, run
from tests.infrastructure.envoy.conftest import Lab

pytestmark = [pytest.mark.egress, pytest.mark.security]


def test_structured_logs_do_not_include_request_secrets(envoy_lab: Lab) -> None:
    marker = "fixture-sensitive-value-do-not-log"
    assert (
        envoy_lab.request(
            kind="http",
            target="http://http.allowed.test/?private=" + marker,
            headers={
                "Authorization": "Bearer " + marker,
                "Cookie": "session=" + marker,
                "Proxy-Authorization": "Basic " + marker,
                "X-Request-ID": marker,
            },
        )["status"]
        == 200
    )
    name, _ = netns(envoy_lab.config)
    time.sleep(1.2)
    value = run([*docker_command(), "logs", name])
    assert marker not in value.stdout + value.stderr
    logs = [json.loads(line) for line in value.stdout.splitlines() if line.startswith("{")]
    assert any(log["listener"] == "http" and log["status"] == 200 for log in logs)
    assert all("correlation_id" in log for log in logs)


def test_fixed_upstream_unavailable_recovers(envoy_lab: Lab) -> None:
    # Isolate only the fake public route in the Envoy namespace, never a host route.
    _, pid = netns(envoy_lab.config)
    namespace_command(pid, ["ip", "route", "replace", "blackhole", "93.184.216.34/32"])
    before = envoy_lab.counters().get("tcp_587", 0)
    try:
        result = envoy_lab.request("mail-relay", kind="smtp")
        assert not result.get("banner")
        assert (
            envoy_lab.request(kind="http", target="http://http.allowed.test/").get("status") != 200
        )
        assert envoy_lab.counters().get("tcp_587", 0) == before
    finally:
        private = next(
            iter(inspect_container(envoy_lab.sink)["NetworkSettings"]["Networks"].values())
        )["IPAddress"]
        namespace_command(pid, ["ip", "route", "replace", "93.184.216.34/32", "via", private])
    assert envoy_lab.request("mail-relay", kind="smtp")["banner"].startswith("220 ")


def test_connection_limit_is_enforced(envoy_lab: Lab) -> None:
    assert envoy_lab.request(kind="hold")["rejected"] > 0
    time.sleep(0.2)
    assert envoy_lab.request(kind="http", target="http://http.allowed.test/")["status"] == 200


def test_z_restart_requires_fresh_guard_and_recovers(envoy_lab: Lab) -> None:
    # Alter Namespace-/Bootnachweis darf einen Neustart nicht freigeben.
    config = envoy_lab.config
    compose(config, ["restart", "cve-egress-proxy"])
    time.sleep(0.5)
    # The original Envoy has no static listeners; its one-shot LDS source is absent.
    assert "error" in envoy_lab.request(kind="http", target="http://http.allowed.test/")
    start(config, envoy_lab.value, {role: envoy_lab.clients[role] for role in CLIENT_SERVICES})
    _, pid = netns(config)
    private = next(iter(inspect_container(envoy_lab.sink)["NetworkSettings"]["Networks"].values()))[
        "IPAddress"
    ]
    namespace_command(pid, ["ip", "route", "add", "93.184.216.34/32", "via", private])
    assert envoy_lab.request(kind="http", target="http://http.allowed.test/")["status"] == 200


def test_zz_reused_ip_does_not_inherit_old_client_binding(envoy_lab: Lab) -> None:
    """Docker-Neuvergabe derselben IP erhält eine andere MAC und keine alte Proxyfreigabe."""
    from tests.infrastructure.envoy.conftest import PYTHON_IMAGE

    lab = envoy_lab
    internal = lab.config.project + "_cve_egress_internal"
    original = inspect_container(lab.clients["importer"])["NetworkSettings"]["Networks"][internal]
    replacement = lab.config.project + "-replacement"
    before = lab.counters().get("tcp_80", 0)
    run([*docker_command(), "network", "disconnect", internal, lab.clients["importer"]])
    created = False
    try:
        run(
            [
                *docker_command(),
                "run",
                "-d",
                "--name",
                replacement,
                "--network",
                internal,
                "--label",
                "org.cve-monitoring.egress-test=" + lab.config.project,
                "--user",
                "65532:65532",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--read-only",
                "-v",
                str(lab.files / "client.py") + ":/fixture/client.py:ro",
                PYTHON_IMAGE,
                "sleep",
                "300",
            ]
        )
        created = True
        current = inspect_container(replacement)["NetworkSettings"]["Networks"][internal]
        assert current["MacAddress"] != original["MacAddress"]
        if current["IPAddress"] != original["IPAddress"]:
            replacement_pid = int(inspect_container(replacement)["State"]["Pid"])
            prefix = current["IPPrefixLen"]
            namespace_command(
                replacement_pid,
                ["ip", "address", "add", original["IPAddress"] + "/" + str(prefix), "dev", "eth0"],
            )
            namespace_command(
                replacement_pid,
                ["ip", "address", "del", current["IPAddress"] + "/" + str(prefix), "dev", "eth0"],
            )
        # Replacement cannot impersonate a service by keeping its old IP or forging HTTP headers.
        lab.clients["replacement"] = replacement
        assert "error" in lab.request(
            "replacement", kind="http", target="http://http.allowed.test/"
        )
        assert lab.counters().get("tcp_80", 0) == before
    finally:
        lab.clients.pop("replacement", None)
        if created:
            run([*docker_command(), "rm", "-f", replacement])
        run([*docker_command(), "network", "connect", internal, lab.clients["importer"]])
        start(lab.config, lab.value, {role: lab.clients[role] for role in CLIENT_SERVICES})
        _, pid = netns(lab.config)
        private = next(iter(inspect_container(lab.sink)["NetworkSettings"]["Networks"].values()))[
            "IPAddress"
        ]
        namespace_command(pid, ["ip", "route", "add", "93.184.216.34/32", "via", private])
    assert lab.request(kind="http", target="http://http.allowed.test/")["status"] == 200


def test_zzz_smtp_idle_timeout_is_enforced_by_envoy(envoy_lab: Lab) -> None:
    """Der Proxy beendet einen angenommenen, aber stummen Smarthost tatsächlich per Idlelimit."""
    import copy
    import re

    lab = envoy_lab
    value = copy.deepcopy(lab.value)
    value["limits"]["idle_timeout_seconds"] = 1
    private = next(iter(inspect_container(lab.sink)["NetworkSettings"]["Networks"].values()))[
        "IPAddress"
    ]
    clients = {role: lab.clients[role] for role in CLIENT_SERVICES}
    try:
        start(lab.config, value, clients)
        _, pid = netns(lab.config)
        namespace_command(pid, ["ip", "route", "add", "93.184.216.34/32", "via", private])
        lab.control(smtp_hang=True)
        before = lab.counters().get("tcp_587", 0)
        assert not lab.request("mail-relay", kind="smtp").get("banner")
        assert lab.counters().get("tcp_587", 0) == before + 1
        metrics = lab.request("status", kind="http", proxy_port=9901, target="/metrics")["body"]
        assert any(
            "idle_timeout" in line and "smtp" in line and float(line.rsplit(" ", 1)[1]) >= 1
            for line in metrics.splitlines()
            if line and not line.startswith("#") and re.search(r"\s[0-9.]+$", line)
        )
    finally:
        lab.control(smtp_hang=False)
        start(lab.config, lab.value, clients)
        _, pid = netns(lab.config)
        namespace_command(pid, ["ip", "route", "add", "93.184.216.34/32", "via", private])
