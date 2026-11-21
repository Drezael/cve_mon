"""Cancel only the deleted server's run processes; expose no working file contents."""

import contextlib
import os
import signal
import sys
from pathlib import Path
from uuid import UUID


def cancel(runs: list[str], root: Path = Path("/work/ansible")) -> int:
    prefixes = tuple("ansible-" + str(UUID(value)) + "-" for value in runs)
    if not prefixes:
        return 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        with contextlib.suppress(OSError, ValueError, IndexError):
            argv = (entry / "cmdline").read_bytes().decode().split("\0")
            if len(argv) >= 4 and argv[1:3] == ["-m", "cve_automation.execute"]:
                path = Path(argv[3])
                if path.parent.parent == root and path.parent.name.startswith(prefixes):
                    os.killpg(int(entry.name), signal.SIGTERM)
    return sum(p.is_dir() and p.name.startswith(prefixes) for p in root.iterdir())


def main() -> None:
    raise SystemExit(1 if cancel(sys.argv[1:]) else 0)


if __name__ == "__main__":
    main()
