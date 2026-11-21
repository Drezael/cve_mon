"""Opaque lookup UUID and independent 256-bit verifiers; only digests persist."""

import hashlib
import hmac
import secrets
from uuid import UUID, uuid4

from .errors import AuthError

SESSION_COOKIE = "__Host-cve-session"
LOGIN_COOKIE = "__Host-cve-login"


def digest(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


def random_value() -> str:
    return secrets.token_urlsafe(32)


def new_token() -> tuple[UUID, str, bytes]:
    uid = uuid4()
    secret = random_value()
    return uid, f"{uid}.{secret}", digest(secret)


def parse_token(value: str | None) -> tuple[UUID, bytes]:
    try:
        if value is None or len(value) > 100:
            raise ValueError
        uid, secret = value.split(".")
        if len(secret) != 43:
            raise ValueError
        return UUID(uid), digest(secret)
    except (ValueError, AttributeError):
        raise AuthError() from None


def verify_digest(value: str, expected: bytes) -> bool:
    return hmac.compare_digest(digest(value), expected)
