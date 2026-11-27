"""Per-user envelope encryption for write-only SSH credentials.

The password wraps a random vault key; a separate service envelope permits unattended
runs. Passwords are never persisted. Only the executor decrypts credential fields.
"""

import base64
import json
import secrets
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from cve_common.ssh_credentials import KeyringError, SSHKeyring

FORMAT = "user-vault-v1"
FIELDS = frozenset({"private_key", "passphrase", "password"})


def seal(key: bytes, value: bytes, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, value, aad)


def unseal(key: bytes, value: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(value[:12], value[12:], aad)


def password_key(password: str, salt: bytes) -> bytes:
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536).derive(
        password.encode("utf-8")
    )


def password_envelope(owner: UUID, password: str, key: bytes) -> tuple[bytes, bytes]:
    salt = secrets.token_bytes(16)
    return salt, seal(password_key(password, salt), key, b"cve:vault:password:v1:" + owner.bytes)


def unlock_password(owner: UUID, password: str, vault: Mapping[str, Any]) -> bytes:
    return unseal(
        password_key(password, bytes(vault["salt"])),
        bytes(vault["password_envelope"]),
        b"cve:vault:password:v1:" + owner.bytes,
    )


class UserVaultKeyring(SSHKeyring):
    def create(self, owner: UUID, password: str) -> dict[str, Any]:
        key = AESGCM.generate_key(bit_length=256)
        salt, wrapped = password_envelope(owner, password, key)
        return {
            "salt": salt,
            "password_envelope": wrapped,
            "key_id": self.active,
            "runtime_envelope": seal(
                self.keys[self.active], key, b"cve:vault:runtime:v1:" + owner.bytes
            ),
        }

    def runtime_key(self, owner: UUID, vault: Mapping[str, Any]) -> bytes:
        try:
            return unseal(
                self.keys[vault["key_id"]],
                bytes(vault["runtime_envelope"]),
                b"cve:vault:runtime:v1:" + owner.bytes,
            )
        except (KeyError, ValueError, TypeError, InvalidTag):
            raise KeyringError("vault_envelope_unavailable") from None


def update_credentials(
    key: bytes, owner: UUID, server: UUID, previous: bytes | None, updates: dict[str, str]
) -> bytes:
    """Preserve opaque fields without ever decrypting them in the API."""
    fields = json.loads(previous) if previous else {}
    for field, value in updates.items():
        if field not in FIELDS:
            raise ValueError("Unsupported vault field")
        if value:
            aad = b"cve:vault:credential:v1:" + owner.bytes + server.bytes + field.encode()
            fields[field] = base64.b64encode(seal(key, value.encode(), aad)).decode("ascii")
        else:
            fields.pop(field, None)
    return json.dumps(fields).encode()


def decrypt_credentials(key: bytes, owner: UUID, server: UUID, value: bytes) -> dict[str, str]:
    result = {}
    for field, cipher in json.loads(value).items():
        if field not in FIELDS:
            raise ValueError("Unsupported vault field")
        aad = b"cve:vault:credential:v1:" + owner.bytes + server.bytes + field.encode()
        result[field] = unseal(key, base64.b64decode(cipher, validate=True), aad).decode()
    return result
