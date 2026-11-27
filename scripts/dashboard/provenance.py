"""Bind dashboard output to every source/configuration input and the pinned toolchain."""

import hashlib
import json
from pathlib import Path


def checksums(paths: list[Path], base: Path) -> dict[str, str]:
    result = {}
    for path in sorted(paths):
        if path.is_symlink():
            raise ValueError("Build inputs and output must not contain symlinks")
        if path.is_file():
            result[str(path.relative_to(base))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def inputs(root: Path) -> dict[str, str]:
    dashboard = root / "services/dashboard"
    paths = [p for folder in ("src", "public") for p in (dashboard / folder).rglob("*")]
    paths += [p for p in dashboard.iterdir() if p.is_file()]
    paths += [root / "scripts/dashboard" / name for name in ("manage.py", "provenance.py")]
    return checksums(paths, root)


def outputs(root: Path) -> dict[str, str]:
    base = root / "services/dashboard/dist"
    if not (base / "index.html").is_file():
        raise ValueError("Built frontend required")
    return checksums(list(base.rglob("*")), base)


def record(root: Path, before: dict[str, str]) -> None:
    if before != inputs(root):
        raise ValueError("Dashboard sources changed during build")
    from scripts.deployment.contracts import atomic

    atomic(root / ".runtime/dashboard-build.json", {"inputs": before, "outputs": outputs(root)})


def verify(root: Path) -> None:
    path = root / ".runtime/dashboard-build.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("Dashboard build provenance missing; rebuild dashboard")
    value = json.loads(path.read_text())
    if value != {"inputs": inputs(root), "outputs": outputs(root)}:
        raise ValueError("Dashboard build is stale or changed; rebuild dashboard")
