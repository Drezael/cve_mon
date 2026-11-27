"Dedicated real TLS/mTLS, API, PostgreSQL and browser identities; no shared resources."

import asyncio
import os
import secrets
import socket
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import UUID, uuid4

import httpx
import pytest
from cve_api.factory import create_app
from cve_api.inventories.service import InventoryService
from cve_api.settings import ApiSettings

from scripts.database import manage as db
from scripts.infrastructure.manage import compose, generate_certificates, render
from scripts.inventory.configuration import settings as inventory_settings
from scripts.security import manage as auth
from scripts.services import manage as api
from tests.authentication.integration.conftest import Browser as AuthBrowser
from tests.authentication.integration.conftest import Lab
from tests.authorization.integration.conftest import Actor, actor, call
from tests.configuration import load_test_config as load_config
from tests.server_administration.integration.conftest import create_server

__all__ = [
    "Browser",
    "Upload",
    "actor",
    "call",
    "create_server",
    "provision",
    "payload",
    "technical",
    "dashboard",
    "upload_lab",
    "browser",
]


@dataclass(kw_only=True)
class Browser(AuthBrowser):
    inventory: InventoryService
    technical_client: httpx.AsyncClient


@pytest.fixture(scope="session")
def upload_lab() -> Iterator[Lab]:
    yield from isolated_upload_lab()


def isolated_upload_lab(initial_values: dict[str, str] | None = None) -> Iterator[Lab]:
    """Reusable isolated project for acceptance scenarios with incompatible source modes."""

    def port() -> str:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return str(s.getsockname()[1])

    project = "cve-db-test-phase11-" + uuid4().hex[:10]
    root = Path(__file__).resolve().parents[3]
    pki = root / ".runtime/upload-tests" / project / "pki"
    cfg = load_config(
        overrides={
            "COMPOSE_PROJECT_NAME": project,
            "STATUS_COLLECTOR_PAUSED": "true",
            "INGRESS_HTTP_PORT": port(),
            "INGRESS_HTTPS_PORT": port(),
            "MAILHOG_HTTP_PORT": port(),
            "SMTP_HOST": "",
            "NGINX_UID": str(os.getuid()),
            "NGINX_GID": str(os.getgid()),
            "TLS_CERT_FILE": str(pki / "server.crt"),
            "TLS_KEY_FILE": str(pki / "server.key"),
            "TLS_TRUST_FILE": str(pki / "server-ca.crt"),
            "CLIENT_CA_FILE": str(pki / "client-ca.crt"),
            "WEB_RATE": "1000r/m",
            "UPLOAD_RATE": "1000r/m",
            "RATE_BURST": "50",
            **(initial_values or {}),
        }
    )
    db.prepare(cfg)
    try:
        compose(cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        db.provision(cfg)
        db.migrate(cfg)
        db.migrate(cfg)
        generate_certificates(cfg, fixtures=True)
        api.prepare(cfg)
        password = secrets.token_urlsafe(24)
        uid = UUID(
            asyncio.run(
                auth.bootstrap(cfg, "upload-initial-admin", "initial@example.test", password)
            )
        )
        api.build(cfg)
        render(cfg)
        compose(cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-api", "cve-nginx"])
        from tests.inventory_upload.integration.technical_gateway import gateway

        with gateway(cfg):
            yield Lab(cfg, password, uid)
    finally:
        reports = root / ".runtime/test-reports"
        reports.mkdir(exist_ok=True, parents=True)
        log = reports / (project + ".log")
        log.write_text(compose(cfg, ["logs", "--no-color", "cve-api"]).stdout)
        log.chmod(0o600)
        db.cleanup_test(cfg)


@pytest.fixture
async def browser(upload_lab: Lab) -> AsyncIterator[Browser]:
    with upload_lab.owner() as c:
        c.execute("DELETE FROM security.auth_rate_limits")
        c.execute("DELETE FROM security.inventory_rate_limits")
    # Each case uses a fresh real leaf while keeping the test CA and CRL stable.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    pki = Path(upload_lab.config.values["TLS_CERT_FILE"]).parent
    ca = x509.load_pem_x509_certificate((pki / "client-ca.crt").read_bytes())
    signing = serialization.load_pem_private_key(
        (pki / "client-ca.key").read_bytes(), password=None
    )
    assert isinstance(signing, rsa.RSAPrivateKey)
    for case_name in ("client", "client-new"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "case-" + uuid4().hex)])
            )
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier("urn:cve-monitoring:upload-case")]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(signing.public_key()),
                critical=False,
            )
            .sign(signing, hashes.SHA256())
        )
        (pki / (case_name + ".crt")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (pki / (case_name + ".key")).write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (pki / (case_name + ".key")).chmod(0o600)
    policy = auth.settings(upload_lab.config)
    inventory = inventory_settings(upload_lab.config)
    app = create_app(
        ApiSettings(
            app_env="test",
            database=upload_lab.database("api_reader"),
            auth=policy,
            inventory=inventory,
            allowed_hosts=[
                "dashboard.example.test",
                "inventory.internal",
                "cve-api",
                "localhost",
                "127.0.0.1",
            ],
        )
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=policy.origin,
            headers={
                "origin": policy.origin,
                "x-cve-auth-gateway": app.state.auth.gateway,
                "x-cve-auth-scheme": "https",
                "x-real-ip": "192.0.2.18",
            },
        ) as client,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=inventory.origin,
            headers={
                "x-cve-inventory-gateway": app.state.inventory.gateway,
                "x-cve-inventory-scheme": "https",
                "x-cve-inventory-verify": "SUCCESS",
                "x-real-ip": "192.0.2.19",
            },
        ) as technical_client,
    ):
        yield Browser(
            client=client,
            service=app.state.auth,
            lab=upload_lab,
            inventory=app.state.inventory,
            technical_client=technical_client,
        )


@dataclass
class Upload:
    administrator: Actor
    server: dict[str, Any]
    client_id: str
    certificate_id: str
    token_id: str
    token: str = field(repr=False)


async def provision(browser: Browser, certificate: str = "client") -> Upload:
    admin = await actor(browser)
    server = await create_server(browser, admin)
    c = await call(
        browser,
        admin,
        "POST",
        "admin/inventory-clients",
        {"name": "controller-" + uuid4().hex[:12]},
    )
    assert c.status_code == 201, c.text
    cid = c.json()["id"]
    pki = Path(browser.lab.config.values["TLS_CERT_FILE"]).parent
    cert = await call(
        browser,
        admin,
        "POST",
        f"admin/inventory-clients/{cid}/certificates",
        {"certificate_pem": (pki / (certificate + ".crt")).read_text()},
    )
    assert cert.status_code == 201, cert.text
    expiry = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    token = await call(
        browser,
        admin,
        "POST",
        f"admin/inventory-clients/{cid}/tokens",
        {"server_id": server["id"], "certificate_id": cert.json()["id"], "expires_at": expiry},
    )
    assert token.status_code == 201, token.text
    return Upload(admin, server, cid, cert.json()["id"], token.json()["id"], token.json()["token"])


def payload(server: str, **extra: Any) -> bytes:
    import json

    value = {
        "schema_version": "1.0",
        "server_id": server,
        "inventory_id": str(uuid4()),
        "captured_at": datetime.now(UTC).isoformat(),
        "collection_status": "complete",
        "collector": {"name": "ansible", "version": "2.19.0"},
        "os": {
            "status": "complete",
            "data": {
                "distribution": "Ubuntu",
                "release": "24.04",
                "architecture": "x86_64",
                "kernel": "6.8",
            },
        },
        "packages": {"status": "complete", "items": []},
        **extra,
    }
    return json.dumps(value).encode()


async def technical(
    browser: Browser,
    upload: Upload,
    raw: bytes,
    *,
    key: str | None = None,
    certificate: str = "client",
    token: str | None = None,
) -> httpx.Response:
    pki = Path(browser.lab.config.values["TLS_CERT_FILE"]).parent
    headers = {
        "authorization": "Bearer " + (token or upload.token),
        "content-type": "application/json",
        "x-cve-inventory-certificate": quote((pki / (certificate + ".crt")).read_text(), safe=""),
    }
    if key is not None:
        headers["idempotency-key"] = key
    return await browser.technical_client.post("/api/v1/inventories", content=raw, headers=headers)


async def dashboard(
    browser: Browser,
    person: Actor,
    server: str,
    raw: bytes,
    *,
    key: str | None = None,
    filename: str = "inventory.json",
    mime: str = "application/json",
) -> httpx.Response:
    headers = {"cookie": "__Host-cve-session=" + person.cookie, "x-csrf-token": person.csrf}
    if key is not None:
        headers["idempotency-key"] = key
    return await browser.client.post(
        "/api/v1/dashboard/inventories/upload",
        data={"server_id": server},
        files={"file": (filename, raw, mime)},
        headers=headers,
    )
