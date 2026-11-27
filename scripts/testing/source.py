"""Bind local and CI evidence to the exact tracked and untracked source contents."""

import hashlib
import subprocess
from pathlib import Path

from scripts.repository_files import repository_files


def identity(root: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    for path in repository_files(root):
        if path.relative_to(root).parts[0] == "docs" or path.suffix == ".md":
            continue  # Prose updates do not invalidate executable/configuration/test evidence.
        digest.update(str(path.relative_to(root)).encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    return {"commit": commit, "source_sha256": digest.hexdigest()}
