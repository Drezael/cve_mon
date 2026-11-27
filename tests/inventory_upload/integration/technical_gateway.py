"""Private mTLS laboratory for the supported internal HTTPS inventory client.

No listener, network, port or SNI is added to the public Dashboard ingress.
"""

import os
import shutil
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts.infrastructure.images import REFERENCES
from scripts.infrastructure.manage import Config, docker_command, run
from tests.resources import remove

GATEWAYS: dict[str, dict[str, Any]] = {}


def reload(project: str) -> None:
    item = GATEWAYS[project]
    cfg, folder = item["config"], item["folder"]
    for field, target in [
        ("CLIENT_CA_FILE", "client-ca.crt"),
        ("CLIENT_CRL_FILE", "client-ca.crl"),
    ]:
        shutil.copyfile(cfg.values[field], folder / target)
    run(
        [
            *docker_command(),
            "exec",
            item["container"],
            "nginx",
            "-s",
            "reload",
            "-c",
            "/etc/technical/nginx.conf",
        ]
    )


@contextmanager
def gateway(config: Config) -> Iterator[None]:
    folder = config.root / ".runtime/technical-tests" / config.project
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "inventory.internal")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("inventory.internal")]), False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(key, hashes.SHA256())
    )
    (folder / "server.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (folder / "server.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (folder / "server.key").chmod(0o600)
    for field, target in [
        ("CLIENT_CA_FILE", "client-ca.crt"),
        ("CLIENT_CRL_FILE", "client-ca.crl"),
    ]:
        shutil.copyfile(config.values[field], folder / target)
    snippets = config.directory / "snippets"
    for source, target in [
        ("inventory-technical-routes.conf", "routes.conf"),
        ("technical-proxy-headers.conf", "headers.conf"),
    ]:
        value = (
            (snippets / source)
            .read_text()
            .replace(
                "/etc/nginx/cve/snippets/technical-proxy-headers.conf",
                "/etc/technical/headers.conf",
            )
        )
        (folder / target).write_text(value)
    (folder / "nginx.conf").write_text("""
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 64; }
http {
 access_log off;
 client_body_temp_path /tmp/body;
 proxy_temp_path /tmp/proxy;
 fastcgi_temp_path /tmp/fastcgi;
 uwsgi_temp_path /tmp/uwsgi;
 scgi_temp_path /tmp/scgi;
 server {
  listen 8443 ssl;
  server_name inventory.internal;
  ssl_certificate /etc/technical/server.crt;
  ssl_certificate_key /etc/technical/server.key;
  ssl_client_certificate /etc/technical/client-ca.crt;
  ssl_crl /etc/technical/client-ca.crl;
  ssl_verify_client on;
  ssl_protocols TLSv1.2 TLSv1.3;
  include /etc/technical/routes.conf;
  location / { return 404; }
 }
}
""")
    name = config.project + "-technical-test"
    try:
        run(
            [
                *docker_command(),
                "run",
                "-d",
                "--name",
                name,
                "--label",
                "org.cve-monitoring.technical-test=" + config.project,
                "--network",
                config.project + "_cve_internal",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                "--mount",
                "type=bind,source=" + str(folder) + ",target=/etc/technical,readonly",
                "--entrypoint",
                "nginx",
                REFERENCES["nginx"],
                "-c",
                "/etc/technical/nginx.conf",
                "-g",
                "daemon off;",
            ]
        )
        import json

        item = json.loads(run([*docker_command(), "inspect", name]).stdout)[0]
        address = item["NetworkSettings"]["Networks"][config.project + "_cve_internal"]["IPAddress"]
        GATEWAYS[config.project] = {
            "config": config,
            "folder": folder,
            "container": name,
            "address": address,
            "port": 8443,
            "ca_file": folder / "server.crt",
        }
        # Native nginx validation/start, then bounded listener readiness without bypassing TLS.
        import socket

        for _ in range(50):
            try:
                with socket.create_connection((address, 8443), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise ValueError("Private technical test listener did not start")
        yield
    finally:
        GATEWAYS.pop(config.project, None)
        remove("container", name, "org.cve-monitoring.technical-test", config.project)
