"""CONNECT ist ein autorisierter Raw-Tunnel; Ziel-TLS prüft der Client weiterhin selbst."""

import pytest

from tests.infrastructure.envoy.conftest import Lab

pytestmark = [pytest.mark.egress, pytest.mark.security]


def test_https_tunnel_and_client_tls(envoy_lab: Lab) -> None:
    result = envoy_lab.request(kind="https", target="tls.allowed.test")
    assert result.get("status") == 200, result
    assert (
        envoy_lab.request("enricher", kind="https", target="alternate.allowed.test")["status"]
        == 200
    )


@pytest.mark.parametrize(
    "target,port",
    [
        ("forbidden.example.test", 443),
        ("tls.allowed.test", 80),
        ("tls.allowed.test", 587),
        ("127.0.0.1", 443),
        ("169.254.169.254", 443),
        ("[::1]", 443),
        ("tls.allowed.test.", 443),
        ("sub.tls.allowed.test", 443),
    ],
)
def test_denied_connect_no_upstream(envoy_lab: Lab, target: str, port: int) -> None:
    before = envoy_lab.counters().get("tcp_443", 0)
    result = envoy_lab.request(kind="https", target=target, target_port=port)
    assert "error" in result
    assert envoy_lab.counters().get("tcp_443", 0) == before


def test_service_cannot_borrow_another_allowlist(envoy_lab: Lab) -> None:
    assert "error" in envoy_lab.request("enricher", kind="https", target="tls.allowed.test")
    assert "error" in envoy_lab.request("intruder", kind="https", target="tls.allowed.test")
