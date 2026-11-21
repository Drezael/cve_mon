"""Actual Postfix transport failures, retry and durable queue behavior."""

import json
import subprocess
import time

import pytest

from scripts.infrastructure import envoy, mail
from scripts.infrastructure.manage import compose
from tests.infrastructure.mail.conftest import Lab

pytestmark = [pytest.mark.mail, pytest.mark.security]


def restore_route(lab: Lab) -> None:
    info = envoy.inspect_container(lab.sink)
    ip = info["NetworkSettings"]["Networks"][lab.config.project + "_cve_egress_external"][
        "IPAddress"
    ]
    _, pid = envoy.netns(lab.config)
    envoy.namespace_command(pid, ["ip", "route", "replace", "93.184.216.34/32", "via", ip])


@pytest.mark.parametrize(
    "mode",
    [
        "wrong_name",
        "foreign_ca",
        "expired",
        "tls11",
        "no_starttls",
        "bad_auth",
        "temp",
        "drop",
        "no_banner",
        "ehlo_timeout",
        "bad_banner",
    ],
)
def test_failed_upstream_keeps_native_queue(mail_lab: Lab, mode: str) -> None:
    lab = mail_lab
    lab.clean()
    lab.control(mode=mode)
    assert lab.submit().get("accepted")
    lab.wait(lambda: any(q["queue_name"] == "deferred" for q in mail.queue(lab.config)), timeout=30)
    status = lab.control()
    assert not status["messages"]
    assert status["counters"].get("auth_before_tls", 0) == 0
    if mode in {"wrong_name", "foreign_ca", "expired", "tls11", "no_starttls"}:
        assert status["counters"].get("auth", 0) == 0
    lab.control(mode="ok")
    mail.exec_mail(lab.config, ["postqueue", "-f"])
    lab.wait(lambda: bool(lab.control()["messages"]))
    lab.wait(lambda: not mail.queue(lab.config))


def test_permanent_failure_bounces_without_original_body(mail_lab: Lab) -> None:
    lab = mail_lab
    lab.clean()
    lab.control(mode="perm")
    assert lab.submit().get("accepted")
    lab.wait(lambda: any(q["sender"] in {"", "MAILER-DAEMON"} for q in mail.queue(lab.config)))
    assert all(q["sender"] != "alerts@notifications.invalid" for q in mail.queue(lab.config))
    lab.control(mode="ok")
    mail.exec_mail(lab.config, ["postqueue", "-f"])
    lab.wait(lambda: bool(lab.control()["messages"]))
    message = lab.control()["messages"][0]
    assert message["sender"] == ""
    assert "private-body-marker" not in message["body"]


def test_queue_survives_restart_recreate_and_recovers(mail_lab: Lab) -> None:
    lab = mail_lab
    lab.clean()
    lab.control(mode="temp")
    assert lab.submit().get("accepted")
    lab.wait(lambda: bool(mail.queue(lab.config)))
    queue_id = mail.queue(lab.config)[0]["queue_id"]
    original = mail.container(lab.config)["Id"]
    compose(lab.config, ["restart", "cve-mail-relay"])
    # Startup is deliberately gated until the operator reinstalls namespace policy.
    for _ in range(50):
        try:
            mail.exec_mail(lab.config, ["test", "-f", "/run/postfix/boot"])
            break
        except Exception:
            time.sleep(0.2)
    current = json.loads((envoy.directory(lab.config) / "policy.json").read_text())
    envoy.start(lab.config, current, {"mail-relay": original})
    mail.release(lab.config)
    restore_route(lab)
    compose(lab.config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-mail-relay"])
    assert mail.container(lab.config)["Id"] == original
    assert any(q["queue_id"] == queue_id for q in mail.queue(lab.config))
    mail.start(lab.config)
    restore_route(lab)
    assert mail.container(lab.config)["Id"] != original
    assert any(q["queue_id"] == queue_id for q in mail.queue(lab.config))
    assert mail.exec_mail(lab.config, ["/opt/cve-mail/healthcheck.sh"]) == ""
    lab.control(mode="ok")
    mail.exec_mail(lab.config, ["postqueue", "-f"])
    lab.wait(lambda: bool(lab.control()["messages"]))
    lab.wait(lambda: not mail.queue(lab.config))


def test_health_capacity_and_log_confidentiality(mail_lab: Lab) -> None:
    lab = mail_lab
    lab.clean()
    assert lab.submit().get("accepted")
    lab.wait(lambda: bool(lab.control()["messages"]))
    logs = compose(lab.config, ["logs", "--no-color", "cve-mail-relay"]).stdout
    for marker in (
        "private-body-marker",
        "recipient@example.invalid",
        "alerts@notifications.invalid",
    ):
        assert marker not in logs
    for name in ("smtp_username", "smtp_password"):
        assert (mail.directory(lab.config) / "secrets" / name).read_text().strip() not in logs
    mail.exec_mail(lab.config, ["postconf", "-e", "queue_minfree = 1152921504606846976"])
    mail.exec_mail(lab.config, ["postfix", "reload"])
    try:
        assert not lab.submit().get("accepted")
        with pytest.raises(subprocess.CalledProcessError):
            mail.exec_mail(lab.config, ["/opt/cve-mail/healthcheck.sh"])
    finally:
        mail.exec_mail(lab.config, ["postconf", "-e", "queue_minfree = 10485760"])
        mail.exec_mail(lab.config, ["postfix", "reload"])


def test_unwritable_queue_fails_health(mail_lab: Lab) -> None:
    lab = mail_lab
    mail.exec_mail(lab.config, ["chmod", "0500", "/var/spool/postfix/incoming"])
    try:
        with pytest.raises(subprocess.CalledProcessError):
            mail.exec_mail(lab.config, ["/opt/cve-mail/healthcheck.sh"])
    finally:
        mail.exec_mail(lab.config, ["chmod", "0700", "/var/spool/postfix/incoming"])
    mail.exec_mail(lab.config, ["/opt/cve-mail/healthcheck.sh"])


def test_ambiguous_data_ack_is_retried(mail_lab: Lab) -> None:
    lab = mail_lab
    lab.clean()
    lab.control(mode="drop_after_data")
    assert lab.submit().get("accepted")
    lab.wait(lambda: bool(lab.control()["messages"]))
    lab.wait(lambda: any(q["queue_name"] == "deferred" for q in mail.queue(lab.config)))
    lab.control(mode="ok")
    mail.exec_mail(lab.config, ["postqueue", "-f"])
    lab.wait(lambda: len(lab.control()["messages"]) >= 2)
    lab.wait(lambda: not mail.queue(lab.config))


def test_native_backoff_retries_without_operator_flush(mail_lab: Lab) -> None:
    lab = mail_lab
    lab.clean()
    lab.control(mode="temp")
    assert lab.submit().get("accepted")
    lab.wait(lambda: any(q["queue_name"] == "deferred" for q in mail.queue(lab.config)))
    lab.control(mode="ok")
    lab.wait(lambda: len(lab.control()["messages"]) == 1, timeout=30)
    lab.wait(lambda: not mail.queue(lab.config))


def test_envoy_outage_preserves_locally_healthy_queue(mail_lab: Lab) -> None:
    lab = mail_lab
    lab.clean()
    compose(lab.config, ["stop", "cve-egress-proxy"])
    try:
        assert lab.submit().get("accepted")
        lab.wait(lambda: any(q["queue_name"] == "deferred" for q in mail.queue(lab.config)))
        mail.exec_mail(lab.config, ["/opt/cve-mail/healthcheck.sh"])
        assert not lab.control()["messages"]
    finally:
        current = json.loads((envoy.directory(lab.config) / "policy.json").read_text())
        envoy.start(lab.config, current, {"mail-relay": mail.container(lab.config)["Id"]})
        restore_route(lab)
    mail.exec_mail(lab.config, ["postqueue", "-f"])
    lab.wait(lambda: len(lab.control()["messages"]) == 1)
    lab.wait(lambda: not mail.queue(lab.config))


def test_native_queue_lifetime_and_double_bounce_are_bounded(mail_lab: Lab) -> None:
    lab = mail_lab
    lab.clean()
    lab.control(mode="temp")
    for key in ("maximal_queue_lifetime", "bounce_queue_lifetime"):
        mail.exec_mail(lab.config, ["postconf", "-e", key + " = 1s"])
    mail.exec_mail(lab.config, ["postfix", "reload"])
    try:
        assert lab.submit().get("accepted")
        lab.wait(lambda: bool(mail.queue(lab.config)))
        lab.wait(lambda: not mail.queue(lab.config), timeout=40)
        assert not lab.control()["messages"]
        logs = compose(lab.config, ["logs", "--no-color", "cve-mail-relay"]).stdout
        assert '"event": "expired"' in logs
    finally:
        for key, value in {
            "maximal_queue_lifetime": "3600s",
            "bounce_queue_lifetime": "60s",
        }.items():
            mail.exec_mail(lab.config, ["postconf", "-e", key + " = " + value])
        mail.exec_mail(lab.config, ["postfix", "reload"])


def test_native_log_metadata_does_not_trust_upstream_status(mail_lab: Lab) -> None:
    """Original rsyslog must retain native status and discard free provider text."""
    lab = mail_lab
    queue_id = "AABBCC112233"
    mail.exec_mail(
        lab.config,
        [
            "logger",
            "-t",
            "cve-postfix/smtp[123]",
            queue_id + ": to=<private@example.invalid>, orig_to=<other@example.invalid>, "
            "relay=provider[93.184.216.34]:587, delay=1, delays=0/0/1/0, "
            "dsn=2.0.0, status=sent (250 accepted status=bounced secret-provider-text)",
        ],
    )

    def records() -> list[dict[str, object]]:
        value = compose(lab.config, ["logs", "--no-log-prefix", "cve-mail-relay"]).stdout
        return [
            json.loads(line)
            for line in value.splitlines()
            if line.startswith("{") and queue_id in line
        ]

    lab.wait(lambda: bool(records()))
    rows = records()
    assert all(row["event"] == "sent" for row in rows)
    assert "private@example.invalid" not in json.dumps(rows)
    assert "secret-provider-text" not in json.dumps(rows)
