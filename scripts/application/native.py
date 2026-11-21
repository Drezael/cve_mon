"""Fetch checksum-pinned original Alpine Git packages before the offline application build."""

import hashlib
import json
import re
import urllib.request
from pathlib import Path

REPOSITORY = "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/"


def download(root: Path, context: Path) -> None:
    lock = json.loads((root / "infrastructure/application/native-packages.lock.json").read_text())
    if lock["version"] != 1 or lock["repository"] != REPOSITORY:
        raise ValueError("Unexpected native package repository")
    destination = context / "apks"
    destination.mkdir(exist_ok=True)
    expected = set()
    checksums = []
    for item in lock["packages"]:
        name, checksum = item["filename"], item["sha256"]
        if not re.fullmatch(r"[a-zA-Z0-9_.+-]+\.apk", name) or not re.fullmatch(
            r"[0-9a-f]{64}", checksum
        ):
            raise ValueError("Invalid native package lock")
        expected.add(name)
        path = destination / name
        if path.is_symlink():
            raise ValueError("Unsafe native package cache")
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
            with urllib.request.urlopen(REPOSITORY + name, timeout=60) as response:
                raw = response.read(33554433)
            if len(raw) > 33554432 or hashlib.sha256(raw).hexdigest() != checksum:
                raise ValueError("Native package checksum mismatch")
            path.write_bytes(raw)
        checksums.append(checksum + "  " + name + "\n")
    for path in destination.iterdir():
        if path.name not in expected:
            raise ValueError("Unexpected native package cache entry")
    (context / "apks.sha256").write_text("".join(checksums))
