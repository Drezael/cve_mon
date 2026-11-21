"""Expired local SMTP certificates renew without losing transport policy or changing keys."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scripts.infrastructure.manage import load_config
from scripts.smtp.certificates import maintain


@pytest.mark.parametrize("renew_ca", [False, True])
def test_local_smtp_expiry_renewal_preserves_policy_and_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, renew_ca: bool
) -> None:
    from scripts.infrastructure import mail
    from scripts.notifications import manage as notifications
    from scripts.smtp import manage as smtp

    base, target = tmp_path / "mail", tmp_path / "notification"
    for p in [base / "pki/private", base / "state", target]:
        p.mkdir(parents=True)
    now = datetime.now(UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SMTP CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=1 if renew_ca else 30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "notification")]))
        .issuer_name(subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    (base / "state/client-ca.crt").write_bytes(ca.public_bytes(pem))
    (base / "state/server.crt").write_bytes(leaf.public_bytes(pem))
    (target / "smtp-client.crt").write_bytes(leaf.public_bytes(pem))
    original_key = key.private_bytes(
        pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    (base / "pki/private/client-ca.key").write_bytes(original_key)
    client = {
        "name": "notification",
        "fingerprint": ":".join(["AB"] * 32),
        "senders": ["monitor@example.test"],
        "enabled": True,
        "purpose": "Test",
    }
    policy: dict[str, Any] = {
        "enabled": True,
        "smarthost": "mailhog.cve.test",
        "port": 1025,
        "clients": [client],
        "recipients": ["owner@example.test"],
        "settings": {},
    }
    (base / "state/policy.json").write_text(json.dumps(policy))
    monkeypatch.setattr(mail, "directory", lambda _: base)
    monkeypatch.setattr(notifications, "directory", lambda _: target)
    reloads: list[bool] = []
    monkeypatch.setattr(smtp, "reload_postfix", lambda _: reloads.append(True))
    config = load_config(overrides={"COMPOSE_PROJECT_NAME": "cve-db-test-certs"})
    assert maintain(config, force=True)
    updated = x509.load_pem_x509_certificate((target / "smtp-client.crt").read_bytes())
    root = x509.load_pem_x509_certificate((base / "state/client-ca.crt").read_bytes())
    updated.verify_directly_issued_by(root)
    assert updated.not_valid_after_utc > now + timedelta(days=10)
    assert updated.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == leaf_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert (base / "pki/private/client-ca.key").read_bytes() == original_key
    after = json.loads((base / "state/policy.json").read_text())
    assert after["clients"][0]["fingerprint"] == ":".join(
        f"{v:02X}" for v in updated.fingerprint(hashes.SHA256())
    )
    after["clients"][0]["fingerprint"] = policy["clients"][0]["fingerprint"]
    assert after == policy
    assert not maintain(config, force=True) and reloads == [True]
