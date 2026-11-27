"""Dedicated versioned AES-GCM SSH envelopes; never reuse MFA keys or AAD."""

import json
import secrets
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cve_common.config.secrets import SecretError, read_secret


class KeyringError(ValueError):
    """Stable diagnostic, with neither secret values nor filesystem paths."""


class SSHKeyring:
    def __init__(self, path: Path) -> None:
        try:
            value = json.loads(read_secret(path).get_secret_value())
            self.active = value["active"]
            self.keys = {k: bytes.fromhex(v) for k, v in value["keys"].items()}
            if (
                not isinstance(self.active, str)
                or self.active not in self.keys
                or any(len(v) != 32 for v in self.keys.values())
            ):
                raise ValueError
        except (SecretError, KeyError, ValueError, TypeError, AttributeError):
            raise KeyringError("ssh_keyring_unavailable") from None

    def encrypt(self, server: UUID, version: int, value: dict[str, Any]) -> tuple[str, bytes]:
        nonce = secrets.token_bytes(12)
        aad = b"cve:ssh:v1:" + server.bytes + str(version).encode()
        return self.active, nonce + AESGCM(self.keys[self.active]).encrypt(
            nonce, json.dumps(value).encode(), aad
        )

    def decrypt(self, server: UUID, version: int, key_id: str, value: bytes) -> dict[str, Any]:
        aad = b"cve:ssh:v1:" + server.bytes + str(version).encode()
        try:
            result: dict[str, Any] = json.loads(
                AESGCM(self.keys[key_id]).decrypt(value[:12], value[12:], aad)
            )
            return result
        except (KeyError, ValueError, InvalidTag):
            raise KeyringError("ssh_envelope_unavailable") from None
