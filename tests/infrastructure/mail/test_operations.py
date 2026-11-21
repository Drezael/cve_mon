"""Operator revocation, secret rotation, backup and namespace boundaries."""

import json
import subprocess
from pathlib import Path

import pytest

from scripts.infrastructure import envoy, mail
from scripts.infrastructure.manage import compose, docker_command, run
from tests.infrastructure.mail.conftest import Lab
from tests.infrastructure.mail.test_reliability import restore_route

pytestmark = [pytest.mark.mail, pytest.mark.security]


def test_certificate_revocation_and_rotation(mail_lab: Lab) -> None:
    lab = mail_lab
    lab.clean()
    path = mail.directory(lab.config) / "state/policy.json"
    original = path.read_text()
    policy = json.loads(original)
    fingerprint = (
        run(
            [
                "openssl",
                "x509",
                "-in",
                str(mail.directory(lab.config) / "pki/rotated.crt"),
                "-sha256",
                "-fingerprint",
                "-noout",
            ]
        )
        .stdout.strip()
        .split("=", 1)[1]
    )
    policy["clients"][0]["fingerprint"] = fingerprint
    try:
        path.write_text(json.dumps(policy))
        mail.start(lab.config)
        restore_route(lab)
        assert not lab.submit().get("accepted")
        assert lab.submit(cert="rotated").get("accepted")
        lab.wait(lambda: bool(lab.control()["messages"]))
    finally:
        path.write_text(original)
        mail.start(lab.config)
        restore_route(lab)


def test_credentials_rotate_without_queue_loss(mail_lab: Lab) -> None:
    lab = mail_lab
    lab.clean()
    secret = mail.directory(lab.config) / "secrets/smtp_password"
    original = secret.read_text()
    try:
        secret.write_text("isolated-rotation-value\n")
        mail.start(lab.config)
        restore_route(lab)
        assert lab.submit().get("accepted")
        lab.wait(lambda: any(q["queue_name"] == "deferred" for q in mail.queue(lab.config)))
        (lab.files / "smtp_password").write_text(secret.read_text())
        mail.exec_mail(lab.config, ["postqueue", "-f"])
        lab.wait(lambda: bool(lab.control()["messages"]))
    finally:
        secret.write_text(original)
        (lab.files / "smtp_password").write_text(original)
        mail.start(lab.config)
        restore_route(lab)


def test_quiesced_backup_checksum_and_non_destructive_restore(
    mail_lab: Lab, tmp_path: Path
) -> None:
    lab = mail_lab
    lab.clean()
    lab.control(mode="temp")
    assert lab.submit().get("accepted")
    lab.wait(lambda: bool(mail.queue(lab.config)))
    identity = mail.queue(lab.config)[0]["queue_id"]
    target = tmp_path / "backup"
    mail.backup(lab.config, target)
    assert (target / "queue.tar").stat().st_mode & 0o077 == 0
    with pytest.raises(subprocess.CalledProcessError):
        mail.restore(lab.config, target)
    mail.start(lab.config)
    restore_route(lab)
    assert any(q["queue_id"] == identity for q in mail.queue(lab.config))
    # Delete only our own synthetic fixture messages, then restore the archived message.
    lab.clean()
    compose(lab.config, ["stop", "cve-mail-relay"])
    # Native PID lock files are ephemeral and are not message data; restore refuses
    # nonempty queue, so use a fresh project-scoped bind directory for this recovery drill.
    info = mail.container(lab.config)
    source = mail.queue_bind(lab.config, info)
    run([*docker_command(), "rm", info["Id"]])
    from scripts.infrastructure.storage import helper

    helper(
        lab.config,
        ["type=bind,source=" + source + ",target=/target"],
        "find /target -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +",
    )
    compose(lab.config, ["create", "cve-mail-relay"])
    mail.restore(lab.config, target)
    mail.start(lab.config)
    restore_route(lab)
    lab.control(mode="ok")
    mail.exec_mail(lab.config, ["postqueue", "-f"])
    lab.wait(lambda: bool(lab.control()["messages"]))
    lab.wait(lambda: not mail.queue(lab.config))


def test_direct_egress_and_wrong_interface_are_denied(mail_lab: Lab) -> None:
    lab = mail_lab
    info = mail.container(lab.config)
    assert set(info["NetworkSettings"]["Networks"]) == {
        lab.config.project + "_cve_internal",
        lab.config.project + "_cve_egress_internal",
    }
    code = (
        "import socket; s=socket.socket(); s.settimeout(1); "
        'print(s.connect_ex(("93.184.216.34",587)))'
    )
    assert mail.exec_mail(lab.config, ["python3", "-c", code]).strip() != "0"
    egress = info["NetworkSettings"]["Networks"][lab.config.project + "_cve_egress_internal"][
        "IPAddress"
    ]
    _, pid = envoy.netns(lab.config)
    result = envoy.namespace_command(
        pid,
        [
            "python3",
            "-c",
            'import socket; s=socket.socket(); s.settimeout(1); print(s.connect_ex(("'
            + egress
            + '",2525)))',
        ],
    )
    assert result.stdout.strip() != "0"
