"""Private bounded file reads and disposable inventory normalization."""

import os
import resource
import stat
import sys
from pathlib import Path
from typing import Any

from cve_automation.inventory_adapter import MAX_BYTES, InventoryError, decode, encode, normalize


def read(path: Path, maximum: int = MAX_BYTES) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise InventoryError("inventory_size")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise InventoryError("inventory_size")
    return raw


def load(path: Path, maximum: int = MAX_BYTES) -> Any:
    raw = read(path, maximum)
    # Check JSON nesting before allocating a Python object graph.
    depth = 0
    quoted = escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            if depth > 48:
                raise InventoryError("inventory_depth")
        elif char in (93, 125):
            depth -= 1
    return decode(raw, maximum)


def main() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (12, 12))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BYTES,) * 2)
    os.umask(0o077)
    try:
        document = normalize(load(Path(sys.argv[1])))
        Path(sys.argv[2]).write_bytes(encode(document))
    except Exception:
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
