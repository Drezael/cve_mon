"""Authenticated envelopes bind secrets to user, server and credential field."""

import json
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag
from cve_common.ssh_credentials import KeyringError
from cve_common.user_vault import (
    UserVaultKeyring,
    decrypt_credentials,
    password_envelope,
    unlock_password,
    update_credentials,
)


def test_user_vault_binding_rotation_and_opaque_updates(tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    path.write_text(json.dumps({"active": "test", "keys": {"test": "ab" * 32}}))
    path.chmod(0o600)
    ring = UserVaultKeyring(path)
    owner, server = uuid4(), uuid4()
    password = "fixture-vault-password-only"  # pragma: allowlist secret -- synthetic fixture
    vault = ring.create(owner, password)
    key = ring.runtime_key(owner, vault)
    assert unlock_password(owner, password, vault) == key
    assert password.encode() not in b"".join(v for v in vault.values() if isinstance(v, bytes))
    with pytest.raises(InvalidTag):
        unlock_password(owner, "wrong-fixture-password", vault)
    with pytest.raises(KeyringError):
        ring.runtime_key(uuid4(), vault)
    fields = {
        "private_key": "fixture-private-key",  # pragma: allowlist secret
        "passphrase": "fixture-phrase",  # pragma: allowlist secret
    }
    encrypted = update_credentials(key, owner, server, None, fields)
    assert all(secret.encode() not in encrypted for secret in fields.values())
    assert decrypt_credentials(key, owner, server, encrypted) == fields
    for user, host in [(uuid4(), server), (owner, uuid4())]:
        with pytest.raises(InvalidTag):
            decrypt_credentials(key, user, host, encrypted)
    tampered = json.loads(encrypted)
    tampered["password"] = tampered.pop("private_key")
    with pytest.raises(InvalidTag):
        decrypt_credentials(key, owner, server, json.dumps(tampered).encode())
    # Reconfiguration copies ciphertext without decoding the old secret.
    changed = update_credentials(key, owner, server, encrypted, {"passphrase": "new-phrase"})
    assert json.loads(changed)["private_key"] == json.loads(encrypted)["private_key"]
    assert decrypt_credentials(key, owner, server, changed)["passphrase"] == "new-phrase"
    salt, wrapped = password_envelope(owner, "new-fixture-password", key)
    rotated = {**vault, "salt": salt, "password_envelope": wrapped}
    assert unlock_password(owner, "new-fixture-password", rotated) == key
    with pytest.raises(InvalidTag):
        unlock_password(owner, password, rotated)
    assert ring.runtime_key(owner, rotated) == key
    assert decrypt_credentials(key, owner, server, changed)["private_key"] == fields["private_key"]


def test_user_vault_rejects_tampered_service_envelope(tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    path.write_text(json.dumps({"active": "1", "keys": {"1": "cd" * 32}}))
    path.chmod(0o600)
    ring = UserVaultKeyring(path)
    owner = uuid4()
    vault = ring.create(owner, "fixture-vault-password-only")
    vault["runtime_envelope"] = bytes(60)
    with pytest.raises(KeyringError):
        ring.runtime_key(owner, vault)
