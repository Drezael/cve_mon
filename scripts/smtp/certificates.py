"""Renew local development SMTP identities before expiry, preserving keys and configuration."""

import json
import time
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from scripts.infrastructure import mail
from scripts.infrastructure.manage import Config

_CHECKED: dict[str, float] = {}


def maintain(config: Config, *, force: bool = False) -> bool:
    from scripts.notifications.manage import directory
    from scripts.smtp.manage import reload_postfix, replace

    if config.values["APP_ENV"] != "development":
        return False
    if not force and _CHECKED.get(config.project, 0) > time.monotonic():
        return False
    base = mail.directory(config)
    target = directory(config)
    paths = [base / "state/client-ca.crt", base / "state/server.crt", target / "smtp-client.crt"]
    if not all(p.exists() for p in paths):
        return False
    if any(p.is_symlink() for p in paths):
        raise ValueError("unsafe_smtp_certificate_path")
    ca, server, client = [x509.load_pem_x509_certificate(p.read_bytes()) for p in paths]
    now = datetime.now(UTC)
    threshold = now + timedelta(days=3)
    renew_ca = ca.not_valid_after_utc <= now + timedelta(days=7)
    if not renew_ca and min(server.not_valid_after_utc, client.not_valid_after_utc) > threshold:
        _CHECKED[config.project] = time.monotonic() + 3600
        return False
    ca_key_path = base / "pki/private/client-ca.key"
    if ca_key_path.is_symlink():
        raise ValueError("unsafe_smtp_certificate_path")
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    if not isinstance(ca_key, RSAPrivateKey):
        raise ValueError("unsupported_smtp_development_ca_key")
    if ca_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != ca.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        raise ValueError("smtp_ca_key_mismatch")

    def renewed(old: x509.Certificate, issuer: x509.Certificate, end: datetime) -> x509.Certificate:
        builder = (
            x509.CertificateBuilder()
            .subject_name(old.subject)
            .issuer_name(issuer.subject)
            .public_key(old.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(end)
        )
        for extension in old.extensions:
            builder = builder.add_extension(extension.value, extension.critical)
        return builder.sign(ca_key, hashes.SHA256())

    if renew_ca:
        ca = renewed(ca, ca, now + timedelta(days=30))
    server = renewed(server, ca, min(ca.not_valid_after_utc, now + timedelta(days=14)))
    client = renewed(client, ca, min(ca.not_valid_after_utc, now + timedelta(days=14)))

    def pem(c: x509.Certificate) -> bytes:
        return c.public_bytes(serialization.Encoding.PEM)

    for path, value in [
        (base / "pki/client-ca.crt", pem(ca)),
        (base / "state/client-ca.crt", pem(ca)),
        (base / "pki/server.crt", pem(server)),
        (base / "state/server.crt", pem(server)),
        (base / "pki/notification.crt", pem(client)),
        (target / "smtp-ca.crt", pem(ca)),
        (target / "smtp-client.crt", pem(client)),
    ]:
        replace(path, value)
    policy_path = base / "state/policy.json"
    policy = json.loads(policy_path.read_text())
    fingerprint = ":".join(f"{v:02X}" for v in client.fingerprint(hashes.SHA256()))
    for entry in policy["clients"]:
        if entry["name"] == "notification":
            entry["fingerprint"] = fingerprint
    mail.validate(policy)
    replace(policy_path, json.dumps(policy).encode())
    reload_postfix(config)
    _CHECKED[config.project] = time.monotonic() + 3600
    return True
