"""Isolierte Phase-2-Fixtures; nur eindeutig eigene Compose-Projekte entfernen."""

import os
import socket
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from scripts.infrastructure.manage import (
    Config,
    compose,
    docker_command,
    generate_certificates,
    nginx_check,
    render,
    run,
)
from tests.configuration import load_test_config as load_config


@pytest.fixture(scope="session")
def infra_config() -> Iterator[Config]:
    root = Path(__file__).resolve().parents[2]
    project = "cve-test-" + uuid.uuid4().hex[:12]

    def port() -> str:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return str(sock.getsockname()[1])

    directory = root / ".runtime/tests" / project / "pki"
    config = load_config(
        root=root,
        overrides={
            "COMPOSE_PROJECT_NAME": project,
            "NGINX_UID": str(os.getuid()),
            "NGINX_GID": str(os.getgid()),
            "INGRESS_HTTP_PORT": port(),
            "INGRESS_HTTPS_PORT": port(),
            "TLS_CERT_FILE": str(directory / "server.crt"),
            "TLS_KEY_FILE": str(directory / "server.key"),
            "TLS_TRUST_FILE": str(directory / "server-ca.crt"),
            "CLIENT_CA_FILE": str(directory / "client-ca.crt"),
            "WEB_RATE": "6000r/m",
            "UPLOAD_RATE": "6000r/m",
            "RATE_BURST": "100",
            "MAX_BODY_SIZE": "1m",
            "DASHBOARD_MAX_BODY_SIZE": "2m",
            "CLIENT_TIMEOUT": "2s",
        },
    )
    # Kein stilles Skip: ein angeforderter Infrastrukturlauf braucht einen erreichbaren Daemon.
    run([*docker_command(), "info", "--format", "{{.ServerVersion}}"])
    generate_certificates(config, fixtures=True)
    render(config)
    nginx_check(config)
    try:
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "30", "cve-nginx"])
        yield config
    finally:
        assert config.project.startswith("cve-test-")
        compose(config, ["down"])
