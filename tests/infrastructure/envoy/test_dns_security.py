"""DNS/CNAME-Rebinding gegen wirkliche, vom Kernel verwendete Zieladressen."""

import time

import pytest

from scripts.infrastructure.envoy import inspect_container, namespace_command, netns
from tests.infrastructure.envoy.conftest import Lab

pytestmark = [pytest.mark.egress, pytest.mark.security]


def set_record(lab: Lab, host: str, record: list[str] | None) -> None:
    records = lab.control()["records"]
    if record is None:
        records.pop(host, None)
    else:
        records[host] = record
    lab.control(records=records)
    time.sleep(2.2)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "169.254.169.254",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "0.0.0.0",
        "100.64.0.1",
        "198.18.0.1",
    ],
)
def test_reserved_dns_results_are_blocked(envoy_lab: Lab, address: str) -> None:
    before = envoy_lab.counters().get("tcp_80", 0)
    try:
        set_record(envoy_lab, "rebind.allowed.test", ["A", address])
        assert (
            envoy_lab.request(kind="http", target="http://rebind.allowed.test/").get("status")
            != 200
        )
        assert envoy_lab.counters().get("tcp_80", 0) == before
    finally:
        set_record(envoy_lab, "rebind.allowed.test", ["A", "93.184.216.34"])


def test_public_to_private_rebinding_and_recovery(envoy_lab: Lab) -> None:
    assert envoy_lab.request(kind="http", target="http://rebind.allowed.test/")["status"] == 200
    info = inspect_container(envoy_lab.sink)
    private = next(iter(info["NetworkSettings"]["Networks"].values()))["IPAddress"]
    before = envoy_lab.counters().get("tcp_80", 0)
    try:
        set_record(envoy_lab, "rebind.allowed.test", ["A", private])
        assert (
            envoy_lab.request(kind="http", target="http://rebind.allowed.test/").get("status")
            != 200
        )
        assert envoy_lab.counters().get("tcp_80", 0) == before
        _, pid = netns(envoy_lab.config)
        rules = namespace_command(pid, ["nft", "list", "table", "inet", "cve_egress"]).stdout
        assert any(
            "ip daddr {" in line and "reject" in line and "counter packets 0 bytes 0" not in line
            for line in rules.splitlines()
        )
    finally:
        set_record(envoy_lab, "rebind.allowed.test", ["A", "93.184.216.34"])
    assert envoy_lab.request(kind="http", target="http://rebind.allowed.test/")["status"] == 200


def test_cname_cannot_hide_private_target(envoy_lab: Lab) -> None:
    private = next(iter(inspect_container(envoy_lab.sink)["NetworkSettings"]["Networks"].values()))[
        "IPAddress"
    ]
    records = envoy_lab.control()["records"]
    records["private.canonical.test"] = ["A", private]
    envoy_lab.control(records=records)
    before = envoy_lab.counters().get("tcp_80", 0)
    try:
        set_record(envoy_lab, "cname.allowed.test", ["CNAME", "private.canonical.test"])
        assert (
            envoy_lab.request(kind="http", target="http://cname.allowed.test/").get("status") != 200
        )
        assert envoy_lab.counters().get("tcp_80", 0) == before
    finally:
        set_record(envoy_lab, "cname.allowed.test", ["A", "93.184.216.34"])


def test_aaaa_only_and_mixed_responses_fail_closed(envoy_lab: Lab) -> None:
    before = envoy_lab.counters().get("tcp_80", 0)
    try:
        set_record(envoy_lab, "ipv6.allowed.test", ["AAAA", "::1"])
        assert (
            envoy_lab.request(kind="http", target="http://ipv6.allowed.test/").get("status") != 200
        )
        assert envoy_lab.counters().get("tcp_80", 0) == before
        set_record(envoy_lab, "ipv6.allowed.test", ["DUAL", "fd00::1"])
        assert envoy_lab.request(kind="http", target="http://ipv6.allowed.test/")["status"] == 200
        assert envoy_lab.counters().get("dns_ipv6.allowed.test_28", 0) == 0
    finally:
        set_record(envoy_lab, "ipv6.allowed.test", ["A", "93.184.216.34"])


def test_failed_lookup_does_not_pick_another_target(envoy_lab: Lab) -> None:
    before = envoy_lab.counters().get("tcp_80", 0)
    assert (
        envoy_lab.request(kind="http", target="http://missing.allowed.test/").get("status") != 200
    )
    assert envoy_lab.counters().get("tcp_80", 0) == before
