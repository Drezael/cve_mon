"""The repository-local internal client uses verified mutual TLS and refuses redirects."""

import ssl
import threading
import urllib.error
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts.ansible.submit import request


@pytest.mark.parametrize("redirect", [False, True])
def test_internal_client_verifies_mtls_and_does_not_forward_redirects(
    tmp_path: Path,
    redirect: bool,
) -> None:
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CVE fixture CA")])
    now = datetime.now(UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(issuer)
        .issuer_name(issuer)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    ca_file = tmp_path / "ca.crt"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for name, usage in (
        ("server", ExtendedKeyUsageOID.SERVER_AUTH),
        ("client", ExtendedKeyUsageOID.CLIENT_AUTH),
    ):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(issuer_key, hashes.SHA256())
        )
        (tmp_path / (name + ".crt")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        target = tmp_path / (name + ".key")
        target.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        target.chmod(0o600)
    token = tmp_path / "token"
    token.write_text("fixture-collector-token")
    token.chmod(0o600)
    seen: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            seen.append(
                {
                    "path": self.path,
                    "token": self.headers["Authorization"],
                    "body": self.rfile.read(int(self.headers["Content-Length"])),
                }
            )
            self.send_response(307 if redirect else 200)
            if redirect:
                self.send_header("Location", "/api/v1/inventories/redirected")
            self.end_headers()
            self.wfile.write(b'{"accepted":true}')

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / "server.crt", tmp_path / "server.key")
    context.load_verify_locations(ca_file)
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    config = {
        "origin": f"https://127.0.0.1:{server.server_port}",
        "ca_file": str(ca_file),
        "certificate_file": str(tmp_path / "client.crt"),
        "key_file": str(tmp_path / "client.key"),
        "token_file": str(token),
    }
    try:
        if redirect:
            with pytest.raises(urllib.error.HTTPError) as error:
                request(config, "/api/v1/inventories", b"{}")
            assert error.value.code == 307
        else:
            assert request(config, "/api/v1/inventories", b"{}") == {"accepted": True}
        assert seen == [
            {
                "path": "/api/v1/inventories",
                "token": "Bearer fixture-collector-token",
                "body": b"{}",
            }
        ]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
