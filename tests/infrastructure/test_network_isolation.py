"""Reale Verbindungstests mit ausschließlich eigenen, temporären Docker-Ressourcen."""

import json
import subprocess

import pytest

from scripts.infrastructure.manage import Config, docker_command, network_definitions, resolved, run

pytestmark = [pytest.mark.infrastructure, pytest.mark.security]


def test_live_network_isolation(infra_config: Config) -> None:
    prefix = infra_config.project + "-probe"
    docker = docker_command()
    image = resolved(infra_config)["services"]["cve-nginx"]["image"]
    networks: list[str] = []
    containers: list[str] = []
    label = "org.cve-monitoring.test=" + prefix
    try:
        definitions = network_definitions(infra_config)
        for key, value in definitions.items():
            name = prefix + "-" + key
            command = [*docker, "network", "create", "--driver", "bridge", "--label", label]
            if value.get("internal"):
                command += ["--internal"]
            run(command + [name])
            networks.append(name)

        def container(suffix: str, network: str, server: bool = False) -> str:
            name = prefix + "-" + suffix
            command = [
                *docker,
                "run",
                "-d",
                "--name",
                name,
                "--label",
                label,
                "--network",
                prefix + "-" + network,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--user",
                "1000:1000",
                "--entrypoint",
                "/bin/sh",
                image,
                "-c",
                "exec nc -lk -p 8090 -e /bin/cat" if server else "exec sleep 300",
            ]
            run(command)
            containers.append(name)
            return name

        server_a = container("server-a", "cve_internal", True)
        client_a = container("client-a", "cve_internal")
        server_b = container("server-b", "cve_data", True)
        client_b = container("client-b", "cve_data")
        external = container("external", "cve_egress_external")

        def ip(name: str) -> str:
            item = json.loads(run([*docker, "inspect", name]).stdout)[0]
            assert not item["HostConfig"]["PortBindings"]
            return str(next(iter(item["NetworkSettings"]["Networks"].values()))["IPAddress"])

        def connects(client: str, address: str, port: str) -> bool:
            result = subprocess.run(
                [*docker, "exec", client, "nc", "-z", "-w", "3", address, port],
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            return result.returncode == 0

        assert connects(client_a, ip(server_a), "8090")
        assert connects(client_b, ip(server_b), "8090")
        assert not connects(client_a, ip(server_b), "8090")
        assert not connects(client_b, ip(server_a), "8090")
        # Positiver Kontrollversuch: der externe Probe-Client erreicht tatsächlich ein Internetziel.
        assert connects(external, "1.1.1.1", "443"), "Externe Kontrollverbindung nicht verfügbar"
        assert not connects(external, ip(server_a), "8090")
        assert not connects(external, ip(server_b), "8090")
        assert not connects(client_a, "1.1.1.1", "443")
        assert not connects(client_b, "1.1.1.1", "443")
        # Health ist aus dem Anwendungsnetz direkt erreichbar, ohne veröffentlichten Port.
        run([*docker, "network", "connect", infra_config.project + "_cve_internal", client_a])
        result = run(
            [*docker, "exec", client_a, "wget", "-qO-", "-T", "3", "http://cve-nginx:8081/healthz"]
        )
        assert json.loads(result.stdout)["status"] == "healthy"
    finally:
        # Nur Namen entfernen, deren Erstellung hier erfolgreich war; Label zusätzlich nachweisen.
        for name in reversed(containers):
            item = json.loads(run([*docker, "inspect", name]).stdout)[0]
            assert item["Config"]["Labels"].get("org.cve-monitoring.test") == prefix
            run([*docker, "rm", "-f", name])
        for name in reversed(networks):
            item = json.loads(run([*docker, "network", "inspect", name]).stdout)[0]
            assert item["Labels"].get("org.cve-monitoring.test") == prefix
            run([*docker, "network", "rm", name])
