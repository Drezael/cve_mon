"""Actual loopback HTTP/TLS, redirect/timeout behavior and explicit target restrictions."""

import ssl
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from cve_common.http.client import ServiceClient

pytestmark = pytest.mark.security


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/slow":
            time.sleep(0.2)
        self.send_response(302 if self.path == "/redirect" else 200)
        if self.path == "/redirect":
            self.send_header("Location", "https://forbidden.example.test")
        self.end_headers()
        with suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(b"controlled-local-service")

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def local_http() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


async def test_http_redirect_timeout_and_close(
    local_http: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://invalid.example.test:9")
    client = ServiceClient({"local": local_http}, timeout=0.05)
    try:
        assert (await client.request("GET", "local")).text == "controlled-local-service"
        assert (await client.request("GET", "local", "/redirect")).status_code == 302
        with pytest.raises(httpx.ReadTimeout):
            await client.request("GET", "local", "/slow")
        with pytest.raises(KeyError):
            await client.request("GET", "unlisted")
        with pytest.raises(ValueError):
            await client.request("GET", "local", "//evil.test")
    finally:
        await client.close()
    assert client.client.is_closed


@pytest.mark.parametrize(
    "origin,options",
    [
        ("http://example.test", {}),
        ("https://example.test", {"external": True, "proxy": "http://evil.test:3128"}),
        ("http://example.test", {"external": True, "proxy": "http://cve-egress-proxy:3128"}),
        # pragma: allowlist nextline secret (synthetic rejection/redaction fixture)
        ("http://user:credential@localhost", {}),
        ("http://localhost/private", {}),
    ],
)
def test_fail_closed_targets(origin: str, options: dict[str, object]) -> None:
    if options.get("external"):
        with pytest.raises(ValueError):
            ServiceClient(
                {"target": origin},
                external=True,
                proxy=str(options["proxy"]) if "proxy" in options else None,
            )
    else:
        with pytest.raises(ValueError):
            ServiceClient({"target": origin})


async def test_tls_verification(tmp_path: Path) -> None:
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = "https://localhost:" + str(server.server_port)
    bad = ServiceClient({"local": origin})
    good = ServiceClient({"local": origin}, ca_file=str(cert))
    try:
        with pytest.raises(httpx.ConnectError):
            await bad.request("GET", "local")
        assert (await good.request("GET", "local")).status_code == 200
    finally:
        await bad.close()
        await good.close()
        server.shutdown()
        server.server_close()
        thread.join()
