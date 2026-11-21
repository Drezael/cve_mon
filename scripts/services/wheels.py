"""Download hash-locked CPython 3.12 runtime wheels for the deployed musl/amd64 platform."""

import sys
from pathlib import Path

from scripts.infrastructure.manage import run


def download_runtime(root: Path, destination: Path) -> None:
    from scripts.hardening.runtime_images import build_at

    build_at(root, "python")
    run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--platform",
            "musllinux_1_1_x86_64",
            "--platform",
            "musllinux_1_2_x86_64",
            "--python-version",
            "3.12",
            "--implementation",
            "cp",
            "--abi",
            "cp312",
            "--only-binary=:all:",
            "--no-deps",
            "--no-build-isolation",
            "--require-hashes",
            "-r",
            str(root / "requirements/runtime.txt"),
            "--dest",
            str(destination),
        ]
    )
