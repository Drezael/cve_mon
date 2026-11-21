"""Server-first und transparente STARTTLS-Aushandlung ohne SMTP-Relaylogik."""

import pytest

from tests.infrastructure.envoy.conftest import Lab

pytestmark = [pytest.mark.egress, pytest.mark.security]


def test_immediate_banner_and_starttls(envoy_lab: Lab) -> None:
    result = envoy_lab.request("mail-relay", kind="smtp", starttls=True)
    assert result["banner"].startswith("220 ")
    assert "250-STARTTLS" in result["ehlo"]
    assert result["starttls"].startswith("220 ")
    assert result["quit"].startswith("221 ")


@pytest.mark.parametrize("role", ["intruder", "importer", "enricher", "n8n", "status"])
def test_unauthorized_smtp_does_not_trigger_server_first_connection(
    envoy_lab: Lab, role: str
) -> None:
    before = envoy_lab.counters().get("tcp_587", 0)
    assert "error" in envoy_lab.request(role, kind="smtp")
    assert envoy_lab.counters().get("tcp_587", 0) == before


def test_wrong_external_smtp_certificate_name_rejected(envoy_lab: Lab) -> None:
    assert (
        envoy_lab.request("mail-relay", kind="smtp", starttls=True, verify_host="wrong.invalid")[
            "error"
        ]
        == "SSLCertVerificationError"
    )
