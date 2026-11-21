"""Private regular files and namespace-bound readiness; no symlink credentials."""

import os
import stat
from pathlib import Path

EnrichmentError = ValueError


def private(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) not in {0o600, 0o400}
            ):
                raise EnrichmentError("unsafe_private_file")
            data = handle.read(8193)
        if len(data) > 8192:
            raise EnrichmentError("private_file_limit")
        return data
    except OSError:
        raise EnrichmentError("private_file_unavailable") from None


def proof(path: Path) -> bool:
    try:
        return private(path).decode().strip() == os.readlink("/proc/self/ns/net")
    except (ValueError, UnicodeError, OSError):
        return False
