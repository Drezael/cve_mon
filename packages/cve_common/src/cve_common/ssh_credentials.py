"""Dedicated versioned AES-GCM SSH envelopes; never reuse MFA keys or AAD."""

import json
import secrets
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cve_common.config.secrets import read_secret


class SSHKeyring:
    def __init__(self, path: Path) -> None:
        value = json.loads(read_secret(path).get_secret_value())
        self.active = value["active"]
        self.keys = {k: bytes.fromhex(v) for k, v in value["keys"].items()}
        if self.active not in self.keys or any(len(v) != 32 for v in self.keys.values()):
            raise ValueError("Invalid SSH keyring")

    def encrypt(self, server: UUID, version: int, value: dict[str, Any]) -> tuple[str, bytes]:
        nonce = secrets.token_bytes(12)
        aad = b"cve:ssh:v1:" + server.bytes + str(version).encode()
        return self.active, nonce + AESGCM(self.keys[self.active]).encrypt(
            nonce, json.dumps(value).encode(), aad
        )

    def decrypt(self, server: UUID, version: int, key_id: str, value: bytes) -> dict[str, Any]:
        aad = b"cve:ssh:v1:" + server.bytes + str(version).encode()
        result: dict[str, Any] = json.loads(
            AESGCM(self.keys[key_id]).decrypt(value[:12], value[12:], aad)
        )
        return result
