"""Health und lesende Metriken ohne allgemeine Adminschnittstelle."""

import pytest

from tests.infrastructure.envoy.conftest import Lab

pytestmark = [pytest.mark.egress, pytest.mark.security]


def test_authorized_health_and_metrics(envoy_lab: Lab) -> None:
    result = envoy_lab.request("status", kind="http", proxy_port=9901, target="/healthz")
    assert result["status"] == 200 and result["body"] == "LIVE\n"
    result = envoy_lab.request("status", kind="http", proxy_port=9901, target="/metrics")
    assert result["status"] == 200 and "envoy_" in result["body"]


@pytest.mark.parametrize("path", ["/quitquitquit", "/config_dump", "/stats", "/ready", "/clusters"])
def test_no_generic_admin_forwarding(envoy_lab: Lab, path: str) -> None:
    assert envoy_lab.request("status", kind="http", proxy_port=9901, target=path)["status"] == 403


def test_other_roles_cannot_use_health_or_admin(envoy_lab: Lab) -> None:
    assert "error" in envoy_lab.request(kind="http", proxy_port=9901, target="/healthz")
    assert "error" in envoy_lab.request("intruder", kind="http", proxy_port=9901, target="/healthz")
    assert (
        envoy_lab.request("status", kind="http", proxy_port=9901, target="/healthz", method="POST")[
            "status"
        ]
        == 403
    )
