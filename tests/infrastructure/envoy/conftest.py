"""Eigene Projekte, echte Envoy-/DNS-/TCP-Sockets und ausschließlich eigene Namespacefilter."""

import json
import os
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from scripts.infrastructure.envoy import (
    CLIENT_SERVICES,
    directory,
    inspect_container,
    namespace_command,
    netns,
    policy,
    start,
)
from scripts.infrastructure.manage import Config, compose, docker_command, load_config, run

PYTHON_IMAGE = "python@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7"


@dataclass
class Lab:
    config: Config
    clients: dict[str, str]
    sink: str
    value: dict[str, Any]
    files: Path

    def request(self, role: str = "importer", **arguments: Any) -> dict[str, Any]:
        result = run(
            [*docker_command(), "exec", "-i", self.clients[role], "python", "/fixture/client.py"],
            input=json.dumps(arguments),
        )
        return dict(json.loads(result.stdout))

    def control(self, **values: Any) -> dict[str, Any]:
        script = (
            "import urllib.request,json,sys; d=json.loads(sys.stdin.read()); "
            'u="http://127.0.0.1:8080/control"; '
            'r=urllib.request.Request(u,data=json.dumps(d).encode(),method="POST") if d else u; '
            'print(urllib.request.urlopen(r).read().decode() or "{}")'
        )
        return dict(
            json.loads(
                run(
                    [*docker_command(), "exec", "-i", self.sink, "python", "-c", script],
                    input=json.dumps(values),
                ).stdout
            )
        )

    def counters(self) -> dict[str, int]:
        return dict(self.control()["counters"])


@pytest.fixture(scope="session")
def envoy_lab() -> Iterator[Lab]:
    config = load_config(
        overrides={"COMPOSE_PROJECT_NAME": "cve-egress-test-" + uuid.uuid4().hex[:10]}
    )
    files = directory(config) / "fixtures"
    files.mkdir(parents=True, mode=0o755)
    fixtures = config.root / "tests/infrastructure/envoy/fixtures"
    for name in ("servers.py", "client.py"):
        (files / name).write_text((fixtures / name).read_text())
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-keyout",
            str(files / "server.key"),
            "-out",
            str(files / "server.crt"),
            "-subj",
            "/CN=tls.allowed.test",
            "-addext",
            (
                "subjectAltName=DNS:tls.allowed.test,DNS:mail.allowed.test,"
                "DNS:rebind.allowed.test,DNS:alternate.allowed.test"
            ),
        ]
    )
    # Testserver root owns fixture-private-key; no production Secret, no client sees the key.
    (files / "server.key").chmod(0o600)
    containers = []
    networks = []
    label = "org.cve-monitoring.egress-test=" + config.project
    try:
        for zone, internal in [("cve_egress_internal", True), ("cve_egress_external", False)]:
            name = config.project + "_" + zone
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
                args += ["--internal"]
            run(args + [name])
            networks.append(name)
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
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,size=8m",
                "-v",
                str(files) + ":/fixture:ro",
                PYTHON_IMAGE,
                "python",
                "/fixture/servers.py",
            ]
        )
        containers.append(sink)
        sinkinfo = inspect_container(sink)
        sinkip = sinkinfo["NetworkSettings"]["Networks"][networks[1]]["IPAddress"]
        # Public-IP alias and route only inside OWN test namespaces: never a host/public route.
        namespace_command(
            int(sinkinfo["State"]["Pid"]), ["ip", "address", "add", "93.184.216.34/32", "dev", "lo"]
        )
        clients = {}
        for role in (*CLIENT_SERVICES, "intruder"):
            name = config.project + "-" + role
            service = CLIENT_SERVICES.get(role, "untrusted")
            run(
                [
                    *docker_command(),
                    "run",
                    "-d",
                    "--name",
                    name,
                    "--label",
                    label,
                    "--label",
                    "com.docker.compose.project=" + config.project,
                    "--label",
                    "com.docker.compose.service=" + service,
                    "--network",
                    networks[0],
                    "--user",
                    "65532:65532",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,size=8m",
                    "-e",
                    "HTTP_PROXY=http://cve-egress-proxy:3128",
                    "-e",
                    "HTTPS_PROXY=http://cve-egress-proxy:3128",
                    "-v",
                    str(files / "client.py") + ":/fixture/client.py:ro",
                    "-v",
                    str(files / "server.crt") + ":/fixture/server.crt:ro",
                    PYTHON_IMAGE,
                    "sleep",
                    "1800",
                ]
            )
            containers.append(name)
            clients[role] = name
        value = policy()
        value["clients"].append("sources")
        value["rules"] = []
        value["dns"] = {"address": sinkip, "port": 53, "refresh_seconds": 1, "timeout_seconds": 1}
        for i, (client, host, protocol) in enumerate(
            [
                ("importer", "http.allowed.test", "http"),
                ("importer", "tls.allowed.test", "https"),
                ("importer", "rebind.allowed.test", "http"),
                ("importer", "cname.allowed.test", "http"),
                ("importer", "ipv6.allowed.test", "http"),
                ("enricher", "alternate.allowed.test", "https"),
                ("importer", "missing.allowed.test", "http"),
                ("sources", "http.allowed.test", "http"),
                ("sources", "tls.allowed.test", "https"),
            ]
        ):
            value["rules"].append(
                {
                    "id": "fixture-" + str(i),
                    "client": client,
                    "host": host,
                    "port": 80 if protocol == "http" else 443,
                    "protocol": protocol,
                    "methods": ["GET", "HEAD"] if protocol == "http" else ["CONNECT"],
                    "enabled": True,
                    "purpose": "Kontrollierter isolierter Testendpunkt",
                }
            )
        value["smtp"] = {
            "enabled": True,
            "client": "mail-relay",
            "host": "mail.allowed.test",
            "port": 587,
            "purpose": "Isolierter SMTP-Testserver",
        }
        # The standard start validates/installs the exact same production namespace rules.
        start(config, value, {role: clients[role] for role in CLIENT_SERVICES})
        _, pid = netns(config)
        namespace_command(pid, ["ip", "route", "add", "93.184.216.34/32", "via", sinkip])
        for _ in range(30):
            result = subprocess.run(
                [*docker_command(), "exec", sink, "test", "-f", "/tmp/fixture-ready"],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                break
            time.sleep(0.1)
        lab = Lab(config, clients, sink, value, files)
        yield lab
    finally:
        try:
            name = compose(config, ["ps", "-a", "-q", "cve-egress-proxy"]).stdout.strip()
            logs = run([*docker_command(), "logs", name])
            (directory(config) / "envoy-test.log").write_text(logs.stdout + logs.stderr)
            logs = run([*docker_command(), "logs", sink])
            (directory(config) / "sink-test.log").write_text(logs.stdout + logs.stderr)
        finally:
            compose(config, ["down"])
        for name in reversed(containers):
            assert (
                inspect_container(name)["Config"]["Labels"].get("org.cve-monitoring.egress-test")
                == config.project
            )
            run([*docker_command(), "rm", "-f", name])
        for name in reversed(networks):
            # Compose may already remove its own labelled networks after clients are removed.
            result = subprocess.run(
                [*docker_command(), "network", "inspect", name],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                assert (
                    json.loads(result.stdout)[0]["Labels"].get("org.cve-monitoring.egress-test")
                    == config.project
                )
                run([*docker_command(), "network", "rm", name])
