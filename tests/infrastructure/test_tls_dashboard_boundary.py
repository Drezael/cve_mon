"""Certbot-style links and dashboard-only HTTPS in disposable Docker projects."""

import http.client
import socket
import ssl
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.infrastructure import storage, tls
from scripts.infrastructure.manage import compose, generate_certificates, load_config, render

pytestmark = pytest.mark.infrastructure


def test_certbot_root_owned_live_links_are_imported_read_only(tmp_path: Path) -> None:
    certbot = tmp_path / "letsencrypt"
    live = certbot / "live/dashboard.example.org"
    archive = certbot / "archive/dashboard.example.org"
    live.mkdir(parents=True)
    archive.mkdir(parents=True)
    (archive / "fullchain1.pem").write_text("certificate-content")
    (archive / "privkey1.pem").write_text("private-key-content")
    for name in ("fullchain", "privkey"):
        (live / (name + ".pem")).symlink_to("../../archive/dashboard.example.org/" + name + "1.pem")
    config = load_config(
        overrides={
            "APP_ENV": "production",
            "TLS_DIR": str(live),
            "SECRETS_BASE": str(tmp_path / "private"),
            "COMPOSE_PROJECT_NAME": "cve-test-tls-" + uuid4().hex[:10],
        }
    )
    try:
        storage.helper(
            config,
            ["type=bind,source=" + str(certbot) + ",target=/target"],
            "chown -R 0:0 /target; chmod 700 /target",
        )
        # Loading config must not need to follow root-protected Certbot links.
        config = load_config(overrides={**config.external_values})
        tls.prepare(config)
        assert Path(config.values["TLS_CERT_FILE"]).read_text() == "certificate-content"
        key = Path(config.values["TLS_KEY_FILE"])
        assert key.read_text() == "private-key-content"
        assert key.stat().st_mode & 0o777 == 0o600
        assert Path(config.values["CLIENT_CA_FILE"]).is_relative_to(config.secrets_base)
    finally:
        storage.remove_tree(config, certbot)


def test_only_dashboard_hostname_is_served(tmp_path: Path) -> None:
    def port() -> str:
        with socket.socket() as connection:
            connection.bind(("127.0.0.1", 0))
            return str(connection.getsockname()[1])

    config = load_config(
        overrides={
            "APP_ENV": "development",
            "COMPOSE_PROJECT_NAME": "cve-test-ingress-" + uuid4().hex[:10],
            "MOUNT_BASE": str(tmp_path / "data"),
            "SECRETS_BASE": str(tmp_path / "private"),
            "TLS_DIR": str(tmp_path / "certificates"),
            "INGRESS_BIND_IP": "127.0.0.1",
            "INGRESS_HTTP_PORT": port(),
            "INGRESS_HTTPS_PORT": port(),
        }
    )
    config = replace(config, initialize_secrets=True)
    generate_certificates(config)
    render(config)
    context = ssl.create_default_context(cafile=str(Path(config.values["TLS_DIR"]) / "ca.crt"))
    address = ("127.0.0.1", int(config.values["INGRESS_HTTPS_PORT"]))
    domain = config.values["DASHBOARD_DOMAIN"]

    def request(path: str) -> int:
        with (
            socket.create_connection(address, timeout=5) as connection,
            context.wrap_socket(connection, server_hostname=domain) as secure,
        ):
            secure.sendall(
                (
                    "GET " + path + " HTTP/1.1\r\nHost: " + domain + "\r\nConnection: close\r\n\r\n"
                ).encode()
            )
            response = http.client.HTTPResponse(secure)
            response.begin()
            return response.status

    try:
        compose(config, ["up", "-d", "--no-deps", "--wait", "cve-nginx"])
        assert request("/") in {200, 503}
        for path in ("/webhook/private", "/rest/settings", "/api/v1/inventories", "/n8n"):
            assert request(path) == 404
        context.check_hostname = False
        for forbidden in ("n8n.example.test", "api.example.test", "inventory.example.test"):
            with (
                socket.create_connection(address, timeout=5) as connection,
                pytest.raises(ssl.SSLError),
            ):
                context.wrap_socket(connection, server_hostname=forbidden)
    finally:
        compose(config, ["down"])
