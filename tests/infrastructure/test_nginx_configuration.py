"""Template-, PKI-, Start-/Reload- und Zertifikatswechseltests."""

import hashlib
import socket
import ssl
import subprocess
import time
from pathlib import Path

import pytest

from scripts.infrastructure.manage import (
    Config,
    certificate_preflight,
    compose,
    docker_command,
    generate_certificates,
    nginx_check,
    reload_nginx,
    render_template,
    run,
)
from tests.infrastructure.client import request


def test_template_preserves_nginx_variables() -> None:
    assert (
        render_template("${N8N_DOMAIN} $host $uri $request_id", {"N8N_DOMAIN": "n8n.example.test"})
        == "n8n.example.test $host $uri $request_id"
    )
    with pytest.raises(ValueError, match="Templatevariable"):
        render_template("${UNDECLARED}", {})


@pytest.mark.infrastructure
def test_image_version_and_modules(infra_config: Config) -> None:
    result = compose(infra_config, ["exec", "-T", "cve-nginx", "nginx", "-V"])
    assert "nginx/1.30.6" in result.stderr
    assert "--with-http_ssl_module" in result.stderr
    assert "TLS SNI support enabled" in result.stderr


@pytest.mark.infrastructure
def test_nginx_configuration_is_valid(infra_config: Config) -> None:
    nginx_check(infra_config)


@pytest.mark.infrastructure
def test_pki_is_private_and_not_overwritten(infra_config: Config) -> None:
    directory = Path(infra_config.values["TLS_CERT_FILE"]).parent
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.glob("*.key")}
    assert hashes
    assert all(p.stat().st_mode & 0o077 == 0 for p in directory.glob("*.key"))
    with pytest.raises(ValueError, match="PKI existiert"):
        generate_certificates(infra_config)
    assert hashes == {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.glob("*.key")
    }


@pytest.mark.infrastructure
@pytest.mark.parametrize("replacement", ["expired-server", "wrong-host", "untrusted-server"])
def test_invalid_replacement_certificates_fail(infra_config: Config, replacement: str) -> None:
    directory = Path(infra_config.values["TLS_CERT_FILE"]).parent
    config = Config(
        infra_config.root,
        {
            **infra_config.values,
            "TLS_CERT_FILE": str(directory / (replacement + ".crt")),
            "TLS_KEY_FILE": str(directory / (replacement + ".key")),
        },
    )
    with pytest.raises(subprocess.CalledProcessError):
        certificate_preflight(config)
    assert request(infra_config).status == 503


@pytest.mark.infrastructure
def test_missing_and_mismatched_key_fail(infra_config: Config) -> None:
    directory = Path(infra_config.values["TLS_CERT_FILE"]).parent
    for key in (directory / "missing.key", directory / "client.key"):
        config = Config(infra_config.root, {**infra_config.values, "TLS_KEY_FILE": str(key)})
        with pytest.raises(ValueError):
            certificate_preflight(config)


@pytest.mark.infrastructure
def test_reload_and_certificate_rotation(infra_config: Config) -> None:
    def fingerprint() -> str:
        context = ssl.create_default_context(cafile=infra_config.values["TLS_TRUST_FILE"])
        with (
            socket.create_connection(
                ("127.0.0.1", int(infra_config.values["INGRESS_HTTPS_PORT"])), timeout=3
            ) as raw,
            context.wrap_socket(
                raw, server_hostname=infra_config.values["DASHBOARD_DOMAIN"]
            ) as wrapped,
        ):
            certificate = wrapped.getpeercert(binary_form=True)
            assert certificate is not None
            return hashlib.sha256(certificate).hexdigest()

    before = fingerprint()
    directory = Path(infra_config.values["TLS_CERT_FILE"]).parent
    rotated = Config(
        infra_config.root,
        {
            **infra_config.values,
            "TLS_CERT_FILE": str(directory / "server-new.crt"),
            "TLS_KEY_FILE": str(directory / "server-new.key"),
        },
    )
    try:
        reload_nginx(rotated)
        for _ in range(30):
            if fingerprint() != before:
                break
            time.sleep(0.1)
        assert fingerprint() != before
        assert request(infra_config).status == 503
    finally:
        reload_nginx(infra_config)


@pytest.mark.infrastructure
def test_bad_config_does_not_replace_running_workers(infra_config: Config) -> None:
    path = infra_config.directory / "http.conf"
    original = path.read_text()
    try:
        path.write_text(original + "\ninvalid_directive;\n")
        result = subprocess.run(
            [
                *docker_command(),
                "compose",
                "-p",
                infra_config.project,
                "-f",
                str(infra_config.root / "compose.yml"),
                "exec",
                "-T",
                "cve-nginx",
                "nginx",
                "-t",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0
        assert request(infra_config).status == 503
    finally:
        path.write_text(original)
    reload_nginx(infra_config)


@pytest.mark.infrastructure
def test_restart_and_idempotent_start(infra_config: Config) -> None:
    compose(infra_config, ["up", "-d", "--wait", "cve-nginx"])
    compose(infra_config, ["restart", "cve-nginx"])
    for _ in range(30):
        try:
            if request(infra_config).status == 503:
                break
        except OSError:
            time.sleep(0.1)
    assert request(infra_config).status == 503
    run([*docker_command(), "version", "--format", "{{.Server.Version}}"])


@pytest.mark.infrastructure
def test_production_rejects_development_ca(infra_config: Config) -> None:
    config = Config(infra_config.root, {**infra_config.values, "APP_ENV": "production"})
    with pytest.raises(ValueError, match="Entwicklungszertifikate"):
        certificate_preflight(config)


@pytest.mark.infrastructure
def test_header_timeout_returns_408(infra_config: Config) -> None:
    with socket.create_connection(
        ("127.0.0.1", int(infra_config.values["INGRESS_HTTP_PORT"])), timeout=5
    ) as sock:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: dashboard.example.test\r\nX-Pending: ")
        response = sock.recv(4096)
        # Nginx schließt unvollständige Header nach dem gesetzten Deadline oder sendet 408.
        assert not response or b"408" in response
