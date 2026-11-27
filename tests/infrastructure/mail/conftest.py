"""Own Postfix queue, direct SMTP and private CA/provider; never production messages."""

import json
import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from scripts.infrastructure import envoy, mail
from scripts.infrastructure.manage import Config, compose, docker_command, load_config, run
from tests.infrastructure.envoy.conftest import PYTHON_IMAGE


@dataclass
class Lab:
    config: Config
    sink: str
    client: str
    files: Path

    def control(self, **values: Any) -> dict[str, Any]:
        code = (
            'import json,sys,urllib.request; d=json.load(sys.stdin);u="http://127.0.0.1:8080/control";'
            'r=urllib.request.Request(u,data=json.dumps(d).encode(),method="POST") if d else u;'
            'print(urllib.request.urlopen(r).read().decode() or "{}")'
        )
        return dict(
            json.loads(
                run(
                    [*docker_command(), "exec", "-i", self.sink, "python", "-c", code],
                    input=json.dumps(values),
                ).stdout
            )
        )

    def submit(self, **values: Any) -> dict[str, Any]:
        return dict(
            json.loads(
                run(
                    [*docker_command(), "exec", "-i", self.client, "python", "/client/client.py"],
                    input=json.dumps(values),
                ).stdout
            )
        )

    def wait(self, predicate: Any, timeout: float = 20) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.3)
        raise AssertionError("SMTP condition did not become true")

    def clean(self) -> None:
        assert self.config.project.startswith("cve-mail-test-")
        mail.exec_mail(self.config, ["postsuper", "-d", "ALL"])
        self.control(mode="ok", messages=[], counters={}, sni=[])


@pytest.fixture(scope="session")
def mail_lab() -> Iterator[Lab]:
    config = load_config(
        overrides={"COMPOSE_PROJECT_NAME": "cve-mail-test-" + uuid.uuid4().hex[:10]}
    )
    mail.build(config)
    mail.prepare(config)
    base = mail.directory(config)
    pki = base / "pki"
    files = base / "fixture"
    files.mkdir(mode=0o755)
    clients = base / "test-clients"
    clients.mkdir(mode=0o755)
    for name, ca, host, is_client, expired in [
        ("upstream", "upstream-ca", "mail.allowed.test", False, False),
        ("wrong", "upstream-ca", "cve-egress-proxy", False, False),
        ("foreign", "foreign-ca", "mail.allowed.test", False, False),
        ("expired", "upstream-ca", "mail.allowed.test", False, True),
        ("unlisted", "client-ca", "unlisted", True, False),
        ("foreign-client", "foreign-ca", "foreign-client", True, False),
        ("expired-client", "client-ca", "expired-client", True, True),
        ("rotated", "client-ca", "rotated", True, False),
    ]:
        mail.certificate(pki, name, ca, host, is_client, expired)
    for name in ("upstream", "wrong", "foreign", "expired"):
        shutil.copyfile(pki / (name + ".crt"), files / (name + ".crt"))
        shutil.copyfile(pki / "private" / (name + ".key"), files / (name + ".key"))
        (files / (name + ".key")).chmod(0o600)
    for name in ("notification", "unlisted", "foreign-client", "expired-client", "rotated"):
        for suffix, source in [
            (".crt", pki / (name + ".crt")),
            (".key", pki / "private" / (name + ".key")),
        ]:
            shutil.copyfile(source, clients / (name + suffix))
            (clients / (name + suffix)).chmod(0o600 if suffix == ".key" else 0o644)
    shutil.copyfile(pki / "client-ca.crt", clients / "client-ca.crt")
    for name in ("smtp_username", "smtp_password"):
        shutil.copyfile(base / "secrets" / name, files / name)
        (files / name).chmod(0o600)
    source = config.root / "tests/infrastructure/mail/fixtures"
    shutil.copyfile(source / "smarthost.py", files / "smarthost.py")
    shutil.copyfile(source / "client.py", clients / "client.py")
    shutil.copyfile(
        config.root / "tests/infrastructure/envoy/fixtures/servers.py", files / "base.py"
    )
    value = {
        "enabled": True,
        "smarthost": "mail.allowed.test",
        "port": 587,
        "clients": [
            {
                "name": "notification",
                "fingerprint": run(
                    [
                        "openssl",
                        "x509",
                        "-in",
                        str(pki / "notification.crt"),
                        "-sha256",
                        "-fingerprint",
                        "-noout",
                    ]
                )
                .stdout.strip()
                .split("=", 1)[1],
                "senders": ["alerts@notifications.invalid"],
                "purpose": "Controlled test notification",
                "enabled": True,
            }
        ],
        "recipients": ["recipient@example.invalid"],
        "settings": {
            "minimal_backoff_time": 2,
            "maximal_backoff_time": 4,
            "queue_run_delay": 2,
            "maximal_queue_lifetime": 3600,
            "bounce_queue_lifetime": 60,
        },
    }
    mail.validate(value)
    (base / "state/policy.json").write_text(json.dumps(value, indent=2))
    names = []
    networks = []
    label = "org.cve-monitoring.mail-test=" + config.project
    try:
        for zone, internal in [
            ("cve_internal", True),
            ("cve_outbound", True),
        ]:
            network = config.project + "_" + zone
            args = [
                *docker_command(),
                "network",
                "create",
                "--label",
                label,
                "--label",
                "com.docker.compose.project=" + config.project,
                "--label",
                "com.docker.compose.network=" + zone,
            ]
            if internal:
                args.append("--internal")
            run(args + [network])
            networks.append(network)
        sink = config.project + "-sink"
        run(
            [
                *docker_command(),
                "run",
                "-d",
                "--name",
                sink,
                "--label",
                label,
                "--network",
                networks[1],
                "--network-alias",
                "mail.allowed.test",
                "--user",
                str(os.getuid()) + ":" + str(os.getgid()),
                "--cap-drop",
                "ALL",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,size=8m",
                "-v",
                str(files) + ":/fixture:ro",
                PYTHON_IMAGE,
                "python",
                "/fixture/smarthost.py",
            ]
        )
        names.append(sink)
        client = config.project + "-client"
        run(
            [
                *docker_command(),
                "run",
                "-d",
                "--name",
                client,
                "--label",
                label,
                "--network",
                networks[0],
                "--user",
                str(os.getuid()) + ":" + str(os.getgid()),
                "--cap-drop",
                "ALL",
                "--read-only",
                "-v",
                str(clients) + ":/client:ro",
                PYTHON_IMAGE,
                "sleep",
                "3600",
            ]
        )
        names.append(client)
        mail.start(config)
        lab = Lab(config, sink, client, files)
        yield lab
    finally:
        for service in ("cve-mail-relay",):
            result = compose(config, ["logs", "--no-color", service])
            (base / (service + ".log")).write_text(result.stdout)
        compose(config, ["down"])
        for name in reversed(names):
            assert (
                envoy.inspect_container(name)["Config"]["Labels"].get(
                    "org.cve-monitoring.mail-test"
                )
                == config.project
            )
            run([*docker_command(), "rm", "-f", name])
        from scripts.infrastructure.storage import remove

        remove(config)
        for network in reversed(networks):
            inspected = subprocess.run(
                [*docker_command(), "network", "inspect", network],
                capture_output=True,
                text=True,
                check=False,
            )
            if inspected.returncode == 0:
                assert (
                    json.loads(inspected.stdout)[0]["Labels"].get("org.cve-monitoring.mail-test")
                    == config.project
                )
                run([*docker_command(), "network", "rm", network])
