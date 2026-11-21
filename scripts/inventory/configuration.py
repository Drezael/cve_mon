"Private ingestion prerequisites and public client-PKI snapshots, never client private keys."

import secrets
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cve_api.inventories.settings import InventorySettings
from cve_api.technical_auth.certificates import crl
from cve_common.config.secrets import read_secret
from cve_common.config.settings import DatabaseSettings

from scripts.database import manage as db
from scripts.infrastructure.manage import Config
from scripts.security.manage import private_write


def development_crl(config: Config) -> None:
    path = Path(config.values["CLIENT_CRL_FILE"])
    now = datetime.now(UTC)
    existing = None
    if path.exists():
        existing = x509.load_pem_x509_crl(path.read_bytes())
        if existing.next_update_utc and existing.next_update_utc > now + timedelta(days=1):
            return
    ca_path = Path(config.values["CLIENT_CA_FILE"])
    key = ca_path.with_suffix(".key")
    if (
        not (
            (ca_path.parent / "development.json").is_file()
            or (ca_path.parent / "managed-client-ca.json").is_file()
        )
        or not key.is_file()
    ):
        raise ValueError("Explicit valid client CRL required")
    ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
    signing = serialization.load_pem_private_key(key.read_bytes(), password=None)
    if not isinstance(signing, rsa.RSAPrivateKey):
        raise ValueError("Development CA requires its existing RSA key")
    now = datetime.now(UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=7))
    )
    revoked_ids = set()
    if existing is not None:
        if existing.issuer != ca.subject or not existing.is_signature_valid(signing.public_key()):
            raise ValueError("Existing CRL is not signed by this managed CA")
        for entry in existing:
            builder = builder.add_revoked_certificate(entry)
            revoked_ids.add(entry.serial_number)
    revoked = ca_path.parent / "revoked-client.crt"
    if (
        revoked.is_file()
        and (cert := x509.load_pem_x509_certificate(revoked.read_bytes())).serial_number
        not in revoked_ids
    ):
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(cert.serial_number)
            .revocation_date(now - timedelta(minutes=1))
            .build()
        )
    value = builder.sign(signing, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(path.suffix + ".new")
    with pending.open("xb") as stream:
        stream.write(value)
    pending.chmod(0o644)
    pending.replace(path)


def prepare(config: Config, base: Path) -> None:
    for name in ["inventory-gateway.key", "inventory-token.key"]:
        path = base / name
        if not path.exists() and config.manages_credentials:
            private_write(path, secrets.token_urlsafe(32))
        if len(read_secret(path).get_secret_value()) < 43:
            raise ValueError("Private inventory key required")
    secret = base / "api_ingest.password"
    if not secret.exists() and config.manages_credentials:
        shutil.copyfile(db.secret_file(config, "api_ingest"), secret)
        secret.chmod(0o600)
    read_secret(secret)
    if Path(config.values["CLIENT_CA_FILE"]).is_file():
        trust(config, base)


def trust(config: Config, base: Path) -> None:
    development_crl(config)
    crl(Path(config.values["CLIENT_CRL_FILE"]), Path(config.values["CLIENT_CA_FILE"]))
    for key, name in [
        ("CLIENT_CA_FILE", "inventory-client-ca.crt"),
        ("CLIENT_CRL_FILE", "inventory-client-ca.crl"),
    ]:
        target = base / name
        target.write_bytes(Path(config.values[key]).read_bytes())
        target.chmod(0o600)


def settings(config: Config) -> InventorySettings:
    base = config.secrets_base / "services" / config.project
    maximum = min(
        int(config.values["INVENTORY_MAX_BYTES"]),
        int(config.values["MAX_BODY_SIZE"][:-1]) * 1048576,
    )
    return InventorySettings(
        database=DatabaseSettings(
            host="cve-postgres",
            hostaddr=db.address(config),
            username="api_ingest",
            password_file=base / "api_ingest.password",
            ca_file=base / "ca.crt",
            pool_size=2,
            statement_timeout_ms=15000,
        ),
        origin="https://inventory.internal",
        gateway_file=base / "inventory-gateway.key",
        token_key_file=base / "inventory-token.key",
        client_ca_file=base / "inventory-client-ca.crt",
        client_crl_file=base / "inventory-client-ca.crl",
        max_bytes=maximum,
        max_request_bytes=min(
            maximum + 1048576, int(config.values["DASHBOARD_MAX_BODY_SIZE"][:-1]) * 1048576
        ),
    )


def routes(config: Config) -> None:
    from scripts.security.manage import render_auth_route

    # Authentication rendering also creates the bounded inventory routes.
    render_auth_route(config)
