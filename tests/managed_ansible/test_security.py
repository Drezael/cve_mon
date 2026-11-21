"""Credentials are bound to one server/version and cannot be reused after profile changes."""

import json
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag
from cve_common.ssh_credentials import SSHKeyring


def test_envelopes_reject_another_server_or_profile_version(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"active": "test", "keys": {"test": "ab" * 32}}))
    path.chmod(0o600)
    ring = SSHKeyring(path)
    server = uuid4()
    value = {"password": "fixture-only"}  # pragma: allowlist secret
    key, ciphertext = ring.encrypt(server, 1, value)
    assert b"fixture-only" not in ciphertext
    assert ring.decrypt(server, 1, key, ciphertext) == value
    for candidate, version in ((uuid4(), 1), (server, 2)):
        with pytest.raises(InvalidTag):
            ring.decrypt(candidate, version, key, ciphertext)
