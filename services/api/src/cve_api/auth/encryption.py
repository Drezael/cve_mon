"""AES-256-GCM with user-bound AAD and versioned private keys outside PostgreSQL."""

import json
import secrets
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cve_common.config.secrets import read_secret

from .errors import AuthError


class Keyring:
    def __init__(self, path: Path) -> None:
        try:
            document = json.loads(read_secret(path).get_secret_value())
            self.active = str(document["active"])
            self.keys = {str(k): bytes.fromhex(v) for k, v in document["keys"].items()}
            if (
                self.active not in self.keys
                or not 1 <= len(self.keys) <= 8
                or any(len(v) != 32 for v in self.keys.values())
            ):
                raise ValueError
        except (ValueError, KeyError, TypeError, AttributeError):
            raise AuthError(503) from None

    def encrypt(self, user: UUID, secret: bytes) -> tuple[str, bytes]:
        nonce = secrets.token_bytes(12)
        return self.active, nonce + AESGCM(self.keys[self.active]).encrypt(
            nonce, secret, b"cve:totp:" + user.bytes
        )

    def decrypt(self, user: UUID, key_id: str, encrypted: bytes) -> bytes:
        try:
            return AESGCM(self.keys[key_id]).decrypt(
                encrypted[:12], encrypted[12:], b"cve:totp:" + user.bytes
            )
        except Exception:
            raise AuthError(503) from None
