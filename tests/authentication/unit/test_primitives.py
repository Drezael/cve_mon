"""Password policy, bounded KDFs, RFC vectors, encryption and opaque browser credentials."""

import asyncio
import json
import secrets
from pathlib import Path
from uuid import uuid4

import pytest
from argon2 import PasswordHasher, Type
from cve_api.auth.encryption import Keyring
from cve_api.auth.errors import AuthError
from cve_api.auth.password_policy import normalize, validate_password
from cve_api.auth.passwords import Passwords
from cve_api.auth.sessions import new_token, parse_token
from cve_api.auth.settings import AuthSettings
from cve_api.auth.totp import code, match, new_secret
from cve_common.config.settings import DatabaseSettings
from pydantic import ValidationError


def settings(tmp_path: Path, **overrides: object) -> AuthSettings:
    values: dict[str, object] = {
        "database": DatabaseSettings(
            host="cve-postgres",
            username="api_security",
            password_file=tmp_path / "db",
            ca_file=tmp_path / "ca",
        ),
        "origin": "https://dashboard.example.test",
        "keyring_file": tmp_path / "keys",
        "gateway_file": tmp_path / "gate",
    }
    return AuthSettings.model_validate({**values, **overrides})


@pytest.mark.parametrize(
    "value",
    [
        "short",
        "a" * 256,
        "passwordpassword",
        "correct horse battery staple",
        "this is a password",
        "x" * 257,
        "ab\0" * 8,
    ],
)
def test_policy_rejects_weak_or_unbounded(value: str) -> None:
    with pytest.raises(AuthError):
        validate_password(value)


@pytest.mark.parametrize(
    "value",
    [
        "é 🍀 Wind bewegt die Blätter",
        "  Space is significant  ",
        "a☀b" * 60,
        "long password with single case",
    ],
)
def test_policy_accepts_unicode_and_spaces(value: str) -> None:
    assert validate_password(value) == normalize(value)


def test_normalization_and_no_truncation() -> None:
    assert normalize("e\u0301") == normalize("é")
    assert normalize(" leading ") != "leading"
    assert validate_password("aabbccdd" * 32) == "aabbccdd" * 32


@pytest.mark.parametrize(
    "timestamp,expected",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_rfc6238_sha1_vectors(timestamp: int, expected: str) -> None:
    assert code(b"12345678901234567890", timestamp // 30, 8) == expected


def test_totp_replay_and_window() -> None:
    secret = new_secret()
    assert len(secret) == 20
    value = code(secret, 100)
    assert match(secret, value, 100, 99) == 100
    assert match(secret, value, 100, 100) is None
    assert match(secret, value, 103, -1) is None
    assert match(secret, "１２３４５６", 100, -1) is None


@pytest.mark.parametrize("bad", [None, "x", "bad." + "x" * 43, str(uuid4()) + ".tiny", "x" * 1000])
def test_malformed_session_tokens(bad: str | None) -> None:
    with pytest.raises(AuthError):
        parse_token(bad)


def test_session_verifiers_are_independent_and_opaque() -> None:
    values = [new_token() for _ in range(100)]
    assert len({v[1] for v in values}) == 100
    for uid, token, verifier in values:
        assert parse_token(token) == (uid, verifier)
        assert len(verifier) == 32 and token.encode() != verifier
        assert len(token.split(".")[1]) == 43


@pytest.mark.parametrize(
    "overrides",
    [
        {"argon_memory": 1024},
        {"argon_concurrency": 3},
        {"totp_window": 2},
        {"admin_idle": 901},
        {"origin": "http://dashboard.example.test"},
        {"origin": "https://dashboard.example.test/path"},
        {"login_limit": 0},
    ],
)
def test_unsafe_policy_rejected(tmp_path: Path, overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        settings(tmp_path, **overrides)


def test_aead_key_rotation_and_user_binding(tmp_path: Path) -> None:
    path = tmp_path / "keys"
    keys = {"old": secrets.token_hex(32), "new": secrets.token_hex(32)}
    path.write_text(json.dumps({"active": "old", "keys": keys}))
    path.chmod(0o600)
    ring = Keyring(path)
    uid = uuid4()
    secret = new_secret()
    key, encrypted = ring.encrypt(uid, secret)
    assert encrypted != secret and key == "old"
    path.write_text(json.dumps({"active": "new", "keys": keys}))
    changed = Keyring(path)
    assert changed.decrypt(uid, key, encrypted) == secret
    assert changed.encrypt(uid, secret)[0] == "new"
    for target, blob in [(uuid4(), encrypted), (uid, encrypted[:-1] + bytes([encrypted[-1] ^ 1]))]:
        with pytest.raises(AuthError):
            changed.decrypt(target, key, blob)
    path.unlink()
    with pytest.raises(AuthError):
        Keyring(path)


async def test_argon_hash_verify_rehash_and_bounded_parallelism(tmp_path: Path) -> None:
    passwords = Passwords(settings(tmp_path))
    await passwords.initialize()
    value = secrets.token_urlsafe(24)
    first, second = await asyncio.gather(passwords.hash(value), passwords.hash(value))
    assert first != second and first.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert await passwords.verify(first, value)
    assert not await passwords.verify(first, value + "x")
    assert not await passwords.verify(None, value)
    assert not await passwords.verify("corrupted hash", value)
    legacy = PasswordHasher(memory_cost=19456, time_cost=1, parallelism=1, type=Type.ID).hash(value)
    assert passwords.needs_rehash(legacy)
    assert await passwords.verify(legacy, value)
    results = await asyncio.gather(*(passwords.verify(first, value) for _ in range(4)))
    assert all(results) and passwords.slots._value == 2


async def test_cancelled_hash_keeps_slot_until_thread_finishes(tmp_path: Path) -> None:
    import threading

    passwords = Passwords(settings(tmp_path, argon_concurrency=1))
    started = threading.Event()
    release = threading.Event()

    def operation() -> str:
        started.set()
        release.wait(2)
        return "finished"

    task = asyncio.create_task(passwords._run(operation))
    for _ in range(100):
        if started.is_set():
            break
        await asyncio.sleep(0.005)
    assert started.is_set()
    task.cancel()
    await asyncio.sleep(0.02)
    assert not task.done() and passwords.slots._value == 0
    with pytest.raises(AuthError) as overloaded:
        await passwords._run(lambda: "should not run")
    assert overloaded.value.status == 429
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert passwords.slots._value == 1


@pytest.mark.parametrize("mode", [0o644, 0o666])
def test_mfa_keyfile_must_remain_private(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "keys"
    path.write_text(json.dumps({"active": "1", "keys": {"1": secrets.token_hex(32)}}))
    path.chmod(mode)
    with pytest.raises(AuthError):
        Keyring(path)


def test_authentication_openapi_is_valid_and_has_no_user_crud_or_reset() -> None:
    import yaml
    from openapi_spec_validator import validate

    root = Path(__file__).resolve().parents[3]
    spec = yaml.safe_load((root / "contracts/api/authentication.openapi.yaml").read_text())
    validate(spec)
    assert len(spec["paths"]) == 13
    assert all(path.startswith("/api/v1/auth/") for path in spec["paths"])
    assert not any(
        "reset" in path or "users" in path or "bootstrap" in path for path in spec["paths"]
    )
    assert spec["components"]["securitySchemes"]["SessionCookie"]["name"] == "__Host-cve-session"
