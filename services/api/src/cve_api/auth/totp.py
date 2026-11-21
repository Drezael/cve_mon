"""RFC 6238 / SHA-1, six digits, 30 seconds; database time and atomic replay state."""

import base64
import hmac
import secrets
import struct
from urllib.parse import quote


def new_secret() -> bytes:
    return secrets.token_bytes(20)


def code(secret: bytes, step: int, digits: int = 6, algorithm: str = "sha1") -> str:
    digest = hmac.digest(secret, struct.pack(">Q", step), algorithm)
    offset = digest[-1] & 15
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def match(secret: bytes, value: str, step: int, last: int, window: int = 1) -> int | None:
    if len(value) != 6 or not value.isascii() or not value.isdigit():
        return None
    accepted = None
    for candidate in range(max(0, step - window), step + window + 1):
        if hmac.compare_digest(code(secret, candidate), value) and candidate > last:
            accepted = candidate
    return accepted


def provisioning(secret: bytes, username: str) -> str:
    encoded = base64.b32encode(secret).decode().rstrip("=")
    return (
        f"otpauth://totp/CVE:{quote(username, safe='')}?secret={encoded}"
        "&issuer=CVE&algorithm=SHA1&digits=6&period=30"
    )
