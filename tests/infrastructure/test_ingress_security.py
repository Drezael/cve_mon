"""Echte HTTPS-/mTLS-, Routing-, Header-, Limit- und Datenschutzprüfungen."""

import json
import socket
import ssl
import time

import pytest

from scripts.infrastructure.manage import Config, compose, docker_command, reload_nginx, run
from tests.infrastructure.client import request

pytestmark = [pytest.mark.infrastructure, pytest.mark.security]


@pytest.mark.parametrize(
    "domain", ["dashboard.example.test", "api.example.test", "n8n.example.test"]
)
def test_hosts_without_backends_and_without_client_certificate(
    infra_config: Config, domain: str
) -> None:
    response = request(infra_config, domain)
    assert response.status == 503
    assert json.loads(response.body)["error"] == "backend_unavailable"


@pytest.mark.parametrize("client", [None, "untrusted-client", "expired-client"])
def test_mtls_rejects_invalid_clients(infra_config: Config, client: str | None) -> None:
    try:
        response = request(
            infra_config, "inventory.example.test", "/api/v1/inventories", "POST", client
        )
    except ssl.SSLError:
        return  # TLS-Verweigerung ist ebenso eine echte Ablehnung wie HTTP 403.
    assert response.status == 403


def test_valid_mtls_reaches_only_unavailable_backend(infra_config: Config) -> None:
    response = request(
        infra_config, "inventory.example.test", "/api/v1/inventories", "POST", "client"
    )
    assert response.status == 503
    assert "accepted" not in response.body


def test_forged_headers_cannot_replace_mtls(infra_config: Config) -> None:
    response = request(
        infra_config,
        "inventory.example.test",
        "/api/v1/inventories",
        "POST",
        headers={
            "X-SSL-Client-Verify": "SUCCESS",
            "X-CVE-Client-Cert": "untrusted",
            "X-Forwarded-For": "127.0.0.1",
        },
    )
    assert response.status == 403
    response = request(
        infra_config,
        "inventory.example.test",
        "/api/v1/inventories",
        "POST",
        "client",
        headers={"X-SSL-Client-Verify": "FAILED"},
    )
    assert response.status == 503  # Der verifizierte TLS-Zustand ist maßgeblich, kein Clientheader.


@pytest.mark.parametrize("path", ["/api/v1/dashboard/admin/servers", "/unknown", "/healthz"])
def test_technical_host_has_no_admin_unknown_or_health_route(
    infra_config: Config, path: str
) -> None:
    assert request(infra_config, "inventory.example.test", path, "GET", "client").status == 404


def test_upload_routes_remain_separate(infra_config: Config) -> None:
    assert (
        request(infra_config, path="/api/v1/dashboard/inventories/upload", method="POST").status
        == 503
    )
    assert request(infra_config, path="/api/v1/inventories", method="POST").status == 404
    assert (
        request(
            infra_config, "api.example.test", "/api/v1/dashboard/inventories/upload", "POST"
        ).status
        == 404
    )
    assert (
        request(infra_config, path="/api/v1/dashboard/admin/servers", method="POST").status == 403
    )
    assert request(infra_config, path="/api/v1/cves").status == 503
    assert request(infra_config, path="/api/v1/not-a-contract").status == 404


def test_unknown_sni_and_host_mismatches_are_rejected(infra_config: Config) -> None:
    with pytest.raises(ssl.SSLError):
        request(infra_config, "unknown.example.test")
    assert request(infra_config, headers={"Host": "api.example.test"}).status == 421
    assert request(infra_config, headers={"Host": "attacker.example.test"}).status == 421
    assert request(infra_config, "attacker.example.test", tls=False).status == 421


def test_no_sni_is_rejected(infra_config: Config) -> None:
    context = ssl.create_default_context(cafile=infra_config.values["TLS_TRUST_FILE"])
    context.check_hostname = False
    with (
        socket.create_connection(
            ("127.0.0.1", int(infra_config.values["INGRESS_HTTPS_PORT"]))
        ) as raw,
        pytest.raises(ssl.SSLError),
    ):
        context.wrap_socket(raw)


def test_redirects_are_fixed_and_plaintext_uploads_not_accepted(infra_config: Config) -> None:
    response = request(infra_config, path="/api/v1/cves", tls=False)
    assert response.status == 308
    assert (
        response.headers["location"]
        == "https://dashboard.example.test:"
        + infra_config.values["INGRESS_HTTPS_PORT"]
        + "/api/v1/cves"
    )
    assert (
        request(
            infra_config, "inventory.example.test", "/api/v1/inventories", "POST", tls=False
        ).status
        == 426
    )


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.*:DeprecationWarning")
@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1])
def test_obsolete_tls_rejected(infra_config: Config, version: ssl.TLSVersion) -> None:
    with pytest.raises(ssl.SSLError):
        request(infra_config, version=version)


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_current_tls_supported(infra_config: Config, version: ssl.TLSVersion) -> None:
    assert request(infra_config, version=version).status == 503


def test_security_headers_and_no_development_hsts(infra_config: Config) -> None:
    for path, expected in [("/", 503), ("/unknown", 404), ("/api/v1/dashboard/admin/servers", 403)]:
        response = request(infra_config, path=path)
        assert response.status == expected
        for name in (
            "content-security-policy",
            "x-content-type-options",
            "referrer-policy",
            "x-frame-options",
            "cache-control",
            "x-request-id",
        ):
            assert response.header_names.count(name) == 1
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "strict-transport-security" not in response.headers
        assert response.headers["server"] == "nginx"


def test_body_limit(infra_config: Config) -> None:
    response = request(
        infra_config,
        path="/api/v1/dashboard/inventories/upload",
        method="POST",
        headers={"Content-Length": "3000000"},
    )
    assert response.status == 413
    assert json.loads(response.body)["error"] == "body_too_large"


def test_rate_limit_is_effective_before_missing_backend(infra_config: Config) -> None:
    restricted = Config(
        infra_config.root, {**infra_config.values, "WEB_RATE": "1r/s", "RATE_BURST": "1"}
    )
    try:
        reload_nginx(restricted)
        time.sleep(0.2)
        results = [request(infra_config) for _ in range(10)]
        assert any(response.status == 429 for response in results)
        assert all(response.status in {429, 503} for response in results)
        assert all(
            "retry-after" in response.headers for response in results if response.status == 429
        )
    finally:
        reload_nginx(infra_config)
        time.sleep(0.2)


def test_health_is_not_public(infra_config: Config) -> None:
    assert request(infra_config, path="/healthz").status == 404
    result = compose(
        infra_config, ["exec", "-T", "cve-nginx", "wget", "-qO-", "http://127.0.0.1:8081/healthz"]
    )
    assert json.loads(result.stdout) == {"status": "healthy"}


def test_logs_do_not_include_authentication_or_query_secrets(infra_config: Config) -> None:
    marker = "synthetic-" + "do-not-log-this-value"
    request(
        infra_config,
        path="/?secret=" + marker,
        headers={"Authorization": "Bearer " + marker, "Cookie": "session=" + marker},
    )
    request(
        infra_config,
        path="/api/v1/dashboard/inventories/upload",
        method="POST",
        body=marker.encode(),
    )
    request(infra_config, path="/unknown?secret=" + marker)
    result = compose(infra_config, ["logs", "--no-log-prefix", "cve-nginx"])
    assert marker not in result.stdout + result.stderr
    records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    assert records
    assert {
        "timestamp",
        "request_id",
        "host",
        "method",
        "path",
        "status",
        "duration",
        "upstream_status",
        "upstream_duration",
        "error_class",
    } <= records[-1].keys()


def test_effective_container_hardening(infra_config: Config) -> None:
    cid = compose(infra_config, ["ps", "-q", "cve-nginx"]).stdout.strip()
    value = json.loads(run([*docker_command(), "inspect", cid]).stdout)[0]
    assert value["HostConfig"]["Privileged"] is False
    assert value["HostConfig"]["ReadonlyRootfs"] is True
    assert value["HostConfig"]["Sysctls"]["net.ipv4.ip_forward"] == "0"
    assert value["HostConfig"]["Sysctls"]["net.ipv6.conf.all.forwarding"] == "0"
    assert value["HostConfig"]["CapDrop"] == ["ALL"]
    assert (
        value["Config"]["User"]
        == infra_config.values["NGINX_UID"] + ":" + infra_config.values["NGINX_GID"]
    )
    assert {
        v.split(infra_config.project + "_")[1] for v in value["NetworkSettings"]["Networks"]
    } == {"cve_ingress", "cve_internal"}
    assert set(value["HostConfig"]["PortBindings"]) == {"8080/tcp", "8443/tcp"}
    assert all(not mount["RW"] for mount in value["Mounts"] if mount["Type"] == "bind")
    assert "docker.sock" not in json.dumps(value["Mounts"])


def test_production_hsts_policy_with_isolated_test_certificate(infra_config: Config) -> None:
    path = infra_config.directory / "snippets/security-headers.conf"
    original = path.read_text()
    try:
        path.write_text(
            original.replace(
                'Strict-Transport-Security ""', 'Strict-Transport-Security "max-age=31536000"'
            )
        )
        compose(infra_config, ["exec", "-T", "cve-nginx", "nginx", "-t"])
        compose(infra_config, ["exec", "-T", "cve-nginx", "nginx", "-s", "reload"])
        time.sleep(0.2)
        response = request(infra_config)
        assert response.headers["strict-transport-security"] == "max-age=31536000"
        assert response.header_names.count("strict-transport-security") == 1
    finally:
        path.write_text(original)
        compose(infra_config, ["exec", "-T", "cve-nginx", "nginx", "-s", "reload"])
        time.sleep(0.2)


def test_missing_host_header_rejected(infra_config: Config) -> None:
    for tls in (False, True):
        port = int(infra_config.values["INGRESS_HTTPS_PORT" if tls else "INGRESS_HTTP_PORT"])
        stream = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            if tls:
                context = ssl.create_default_context(cafile=infra_config.values["TLS_TRUST_FILE"])
                stream = context.wrap_socket(stream, server_hostname="dashboard.example.test")
            stream.sendall(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
            assert b"400" in stream.recv(4096).split(b"\r\n", 1)[0]
        finally:
            stream.close()


def test_frontend_chunks_do_not_exhaust_dynamic_request_budget(infra_config: Config) -> None:
    from concurrent.futures import ThreadPoolExecutor

    assert infra_config.project.startswith("cve-test-")
    restricted = Config(
        infra_config.root, {**infra_config.values, "WEB_RATE": "1r/s", "RATE_BURST": "1"}
    )
    index = infra_config.directory / "dashboard/index.html"
    asset = infra_config.directory / "dashboard/assets/rate-regression.js"
    previous = index.read_bytes() if index.exists() else None
    asset.parent.mkdir(parents=True, exist_ok=True)
    asset.write_text("export const synthetic = true;")
    index.write_text("<!doctype html><title>Controlled static rate fixture</title>")
    try:
        reload_nginx(restricted)
        time.sleep(0.2)
        with ThreadPoolExecutor(max_workers=4) as pool:
            chunks = list(
                pool.map(
                    lambda _: request(restricted, path="/assets/rate-regression.js"),
                    range(20),
                )
            )
        assert all(response.status == 200 for response in chunks)
        pages = [request(restricted) for _ in range(10)]
        assert any(response.status == 429 for response in pages)
        assert all(response.status in {200, 429} for response in pages)
    finally:
        asset.unlink()
        if previous is None:
            index.unlink()
        else:
            index.write_bytes(previous)
        reload_nginx(infra_config)
