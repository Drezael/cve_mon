"""Validate effective native Postfix configuration and container hardening."""

import pytest

from scripts.infrastructure import mail
from tests.infrastructure.mail.conftest import Lab

pytestmark = [pytest.mark.mail, pytest.mark.security]


def test_effective_native_configuration(mail_lab: Lab) -> None:
    lab = mail_lab
    for key, expected in {
        "relayhost": "[cve-egress-proxy]:1587",
        "mynetworks": "",
        "relay_domains": "",
        "mydestination": "",
        "smtp_fallback_relay": "",
        "transport_maps": "",
        "smtpd_tls_security_level": "encrypt",
        "smtpd_tls_req_ccert": "yes",
        "smtp_tls_security_level": "secure",
        "smtp_sasl_security_options": "noanonymous,noplaintext",
        "smtp_sasl_tls_verified_security_options": "noanonymous",
        "smtp_bind_address": "0.0.0.0",
        "bounce_size_limit": "1",
    }.items():
        assert mail.exec_mail(lab.config, ["postconf", "-h", key]).strip() == expected
    tls = mail.exec_mail(lab.config, ["cat", "/run/postfix/tls-policy"])
    assert "secure match=mail.allowed.test servername=mail.allowed.test" in tls
    native = mail.exec_mail(lab.config, ["postconf", "-M"])
    inet = [line.split()[0] for line in native.splitlines() if line.split()[1] == "inet"]
    assert inet == ["2525"]
    info = mail.container(lab.config)
    assert info["HostConfig"]["ReadonlyRootfs"]
    assert not info["HostConfig"]["Privileged"]
    assert not info["HostConfig"]["PortBindings"]
    assert {c.removeprefix("CAP_") for c in info["HostConfig"]["CapAdd"]} == mail.CAPABILITIES
    assert not info["Config"]["Env"] or all("SMTP_" not in v for v in info["Config"]["Env"])
    assert not any("test-clients" in m["Source"] or "pki" in m["Source"] for m in info["Mounts"])
    assert (
        mail.exec_mail(lab.config, ["stat", "-c", "%a", "/run/postfix/sasl-passwd"]).strip()
        == "640"
    )
    assert "3.11.7" in mail.exec_mail(lab.config, ["postconf", "-h", "mail_version"])
