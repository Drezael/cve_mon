"""Keep mutable bind data under MOUNT_BASE and read-only inputs in the repository."""

import fcntl
import json
import os
from pathlib import Path

from scripts.infrastructure.manage import Config, docker_command, run

DATA_MOUNTS = (
    ("storage", ""),
    ("acme", ""),
    ("n8n", "data"),
    ("cve-importer", "scratch"),
    ("cve-enricher", "scratch"),
    ("status", "postfix"),
)


def data_paths(config: Config, base: Path | None = None) -> list[Path]:
    return [
        (base or config.mount_base) / bucket / config.project / relative
        for bucket, relative in DATA_MOUNTS
    ]


def checked(path: Path) -> None:
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError("MOUNT_BASE-Pfade dürfen keine Symlinks enthalten")


def ensure_directory(config: Config, path: Path) -> None:
    from scripts.infrastructure.storage import helper

    checked(path)
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except PermissionError:
        # Permit /mnt owned by root without changing that directory's ownership.
        if not path.parent.is_dir() or path.parent == Path("/"):
            raise ValueError(
                "MOUNT_BASE zuerst als eigenes beschreibbares Verzeichnis anlegen"
            ) from None
        helper(
            config,
            ["type=bind,source=" + str(path.parent) + ",target=/parent"],
            f"mkdir -p /parent/{path.name}; "
            f"chown {os.getuid()}:{os.getgid()} /parent/{path.name}; "
            f"chmod 700 /parent/{path.name}",
        )


def prepare(config: Config) -> None:
    """Relocate only mutable data; private read-only configurations stay in the checkout."""
    from scripts.deployment.contracts import atomic
    from scripts.infrastructure.storage import helper

    base = config.mount_base
    checked(base)
    state = config.root / ".runtime/mount-locations"
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state / (config.project + ".lock")).open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        marker = state / (config.project + ".json")
        previous = config.root / ".runtime"
        if marker.exists():
            previous = Path(json.loads(marker.read_text())["mount_base"])
        if previous != base:
            active = run(
                [
                    *docker_command(),
                    "ps",
                    "-q",
                    "--filter",
                    "label=com.docker.compose.project=" + config.project,
                ]
            ).stdout
            if active.strip():
                raise ValueError("Vor Änderung von MOUNT_BASE den bisherigen Stack stoppen")
        ensure_directory(config, base)
        for (bucket, relative), source, target in zip(
            DATA_MOUNTS, data_paths(config, previous), data_paths(config), strict=True
        ):
            ensure_directory(config, base / bucket)
            # Storage's individual data directories are initialized by storage.prepare.
            if relative:
                ensure_directory(config, target.parent)
            checked(source)
            checked(target)
            if source == target or not source.exists() or target.exists():
                continue
            staging = target.with_name(".moving-" + target.name)
            checked(staging)
            staging.mkdir(mode=0o700, exist_ok=True)
            print("Daten-Mount übernehmen: " + bucket + "/" + config.project, flush=True)
            helper(
                config,
                [
                    "type=bind,source=" + str(source) + ",target=/source,readonly",
                    "type=bind,source=" + str(staging) + ",target=/target",
                ],
                "set -o pipefail; tar --exclude=./postgres-tls -cpf - -C /source . "
                "| tar -xpf - -C /target",
            )
            staging.rename(target)
        atomic(marker, {"mount_base": str(base), "layout": "mutable-only"})
