"""Read only explicitly named private regular files without following final symlinks."""

import os
import stat
from pathlib import Path

from pydantic import SecretStr


class SecretError(ValueError):
    """Safe error; never contains filenames, values or underlying OS diagnostics."""


def read_secret(path: Path) -> SecretStr:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
                raise SecretError("Private regular secret file required")
            data = stream.read(4097)
        if len(data) > 4096:
            raise SecretError("Invalid secret length")
        text = data.decode("utf-8").removesuffix("\n")
        if not text or any(c in text for c in "\r\n\0"):
            raise SecretError("Single nonempty secret required")
        return SecretStr(text)
    except (OSError, UnicodeError):
        raise SecretError("Secret unavailable or invalid") from None
