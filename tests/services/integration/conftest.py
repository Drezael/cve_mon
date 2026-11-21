"""Independent PostgreSQL/API/Nginx project; cleanup checks the existing DB-test ownership guard."""

import os
import socket
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from cve_common.config.settings import DatabaseSettings

from scripts.database import manage as db
from scripts.infrastructure.manage import (
    Config,
    compose,
    generate_certificates,
    render,
)
from scripts.services import manage as api
from tests.configuration import load_test_config as load_config


@dataclass
class Lab:
    config: Config

    def settings(self, role: str = "api_reader", **overrides: object) -> DatabaseSettings:
        values: dict[str, object] = {
            "host": "cve-postgres",
            "hostaddr": db.address(self.config),
            "username": role,
            "password_file": db.secret_file(self.config, role),
            "ca_file": db.workdir(self.config) / "tls/ca.crt",
        }
        return DatabaseSettings.model_validate({**values, **overrides})


@pytest.fixture(scope="session")
def service_lab() -> Iterator[Lab]:
    project = "cve-db-test-phase06-" + uuid.uuid4().hex[:10]
    root = Path(__file__).resolve().parents[3]
    pki = root / ".runtime/service-tests" / project / "pki"

    def port() -> str:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return str(sock.getsockname()[1])

    config = load_config(
        overrides={
            "COMPOSE_PROJECT_NAME": project,
            "NGINX_UID": str(os.getuid()),
            "NGINX_GID": str(os.getgid()),
            "INGRESS_HTTP_PORT": port(),
            "INGRESS_HTTPS_PORT": port(),
            "TLS_CERT_FILE": str(pki / "server.crt"),
            "TLS_KEY_FILE": str(pki / "server.key"),
            "TLS_TRUST_FILE": str(pki / "server-ca.crt"),
            "CLIENT_CA_FILE": str(pki / "client-ca.crt"),
        }
    )
    db.prepare(config)
    try:
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        db.provision(config)
        db.migrate(config)
        api.build(config)
        api.prepare(config)
        generate_certificates(config)
        render(config)
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-api", "cve-nginx"])
        yield Lab(config)
    finally:
        folder = root / ".runtime/test-reports"
        folder.mkdir(exist_ok=True, parents=True)
        (folder / (project + ".log")).write_text(
            compose(config, ["logs", "--no-color", "cve-api"]).stdout
        )
        db.cleanup_test(config)
