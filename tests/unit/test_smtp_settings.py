"""SMTP inputs and credential envelopes cannot become arbitrary network or audit payloads."""

import json
import secrets
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag
from cve_common.smtp_settings import SMTPConfig, SMTPKeyring, SMTPUpdate
from pydantic import ValidationError


@pytest.mark.parametrize(
    "host",
    [
        "https://mail.example.org/path",
        "127.0.0.1",
        "[::1]",
        "mail.example.org\nignored",
        "*.example.org",
    ],
)
def test_smtp_rejects_urls_addresses_and_host_injection(host: str) -> None:
    with pytest.raises(ValidationError):
        SMTPConfig(host=host)


def test_smtp_enabled_requires_complete_verified_transport_settings() -> None:
    with pytest.raises(ValidationError):
        SMTPConfig(enabled=True)
    with pytest.raises(ValidationError):
        SMTPConfig(port=465)
    config = SMTPConfig(
        enabled=True,
        host="SMTP.EXAMPLE.ORG",
        sender="security@example.org",
        recipients=["user@example.org", "user@example.org"],
    )
    assert config.host == "smtp.example.org" and config.recipients == ["user@example.org"]


def test_smtp_secret_repr_and_aad_tampering(tmp_path: Path) -> None:
    secret = secrets.token_urlsafe(32)
    model = SMTPUpdate.model_validate({"version": 0, "password": secret})
    assert secret not in repr(model)
    path = tmp_path / "smtp-keys.json"
    path.write_text(json.dumps({"active": "1", "keys": {"1": secrets.token_hex(32)}}))
    path.chmod(0o600)
    ring = SMTPKeyring(path)
    identity = uuid4()
    key, cipher = ring.encrypt(identity, {"username": "fixture", "password": secret})
    assert secret.encode() not in cipher
    assert ring.decrypt(identity, key, cipher)["password"] == secret
    with pytest.raises(InvalidTag):
        ring.decrypt(uuid4(), key, cipher)
    with pytest.raises(InvalidTag):
        ring.decrypt(identity, key, cipher[:-1] + bytes([cipher[-1] ^ 1]))


@pytest.mark.parametrize(
    "host,port,expected",
    [
        ("mailhog.cve.test", 1025, True),
        ("smtp.example.org", 1025, False),
        ("mailhog.cve.test", 587, False),
        ("mailhog.cve.test.attacker.org", 1025, False),
    ],
)
def test_unencrypted_capture_is_limited_to_the_fixed_mailhog_endpoint(
    host: str, port: int, expected: bool
) -> None:
    assert SMTPConfig(host=host, port=port).is_mailhog is expected
