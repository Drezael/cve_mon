"""NFC passwords, 15–256 Unicode codepoints and local common-password rejection."""

import hashlib
import unicodedata
from importlib.resources import files

from .errors import AuthError


def normalize(password: str) -> str:
    return unicodedata.normalize("NFC", password)


def validate_password(password: str, username: str = "") -> str:
    value = normalize(password)
    weak = set(files("cve_api.auth").joinpath("password-blocklist.txt").read_text().splitlines())
    folded = value.casefold()
    expected = unicodedata.normalize("NFKC", username).strip().casefold()
    if (
        not 15 <= len(value) <= 256
        or len(value.encode()) > 1024
        or ("sha256:" + hashlib.sha256(folded.encode()).hexdigest()) in weak
        or len(set(folded)) == 1
        or (expected and folded == expected)
        or "\x00" in value
    ):
        raise AuthError(422)
    return value
