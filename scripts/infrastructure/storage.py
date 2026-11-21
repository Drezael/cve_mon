"""Project-local persistent bind mounts and offline adoption of legacy Docker volumes."""

import json
import os
import subprocess
from pathlib import Path

from scripts.infrastructure.manage import Config, docker_command, run

# Keep live data separate from configuration snapshots and their permission metadata.
STORES = {
    "postgres_data": ("postgres-data", "cve-postgres"),
    "postgres_tls": ("postgres-tls", "cve-postgres"),
    "cve_postfix_queue": ("postfix-queue", "cve-mail-relay"),
    "cve_mailhog_data": ("mailhog", "cve-mailhog"),
}


def directory(config: Config) -> Path:
    return config.mount_base / "storage" / config.project


def path(config: Config, logical: str) -> Path:
    if logical == "postgres_tls":
        return config.secrets_base / "storage" / config.project / "postgres-tls"
    return directory(config) / STORES[logical][0]


def checked(config: Config) -> Path:
    base = directory(config)
    for item in (base, *base.parents):
        if item.is_symlink():
            raise ValueError("Persistent storage must not contain symlink parents")
        if item == config.root:
            break
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    return base


def image_tmpfs(image: str) -> list[str]:
    """Cover image-declared VOLUME paths without allocating anonymous volumes."""
    metadata = json.loads(run([*docker_command(), "image", "inspect", image]).stdout)[0]
    arguments = []
    for destination in metadata["Config"].get("Volumes") or {}:
        arguments += ["--tmpfs", destination.rstrip("/") + ":rw,noexec,nosuid,size=16m"]
    return arguments


def helper(config: Config, mounts: list[str], command: str, *, image: str | None = None) -> None:
    from scripts.hardening.runtime_images import ensure
    from scripts.infrastructure.images import REFERENCES

    image = image or REFERENCES["postgres"]
    ensure(image)
    arguments = [*docker_command(), "run", "--rm", "--network", "none", "--read-only"]
    arguments += image_tmpfs(image)
    for mount in mounts:
        arguments += ["--mount", mount]
    subprocess.run(
        [*arguments, "--entrypoint", "/bin/sh", image, "-ec", command],
        check=True,
        text=True,
        capture_output=True,
        timeout=1800,
    )


def prepare(config: Config, services: list[str]) -> None:
    """Copy a stopped legacy store once, keeping its original volume untouched."""
    selected = {key: item for key, item in STORES.items() if item[1] in services}
    if not selected:
        return
    checked(config)
    available = set(
        run([*docker_command(), "volume", "ls", "--format", "{{.Name}}"]).stdout.splitlines()
    )
    for logical, (folder, _service) in selected.items():
        target = path(config, logical)
        base = target.parent
        from scripts.infrastructure.mounts import checked as checked_path

        checked_path(base)
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.is_symlink():
            raise ValueError("Persistent data directory must not be a symlink")
        if target.exists():
            if not target.is_dir():
                raise ValueError("Persistent data directory required")
            continue
        legacy = config.project + "_" + logical
        stage = base / (".migrating-" + folder)
        if stage.is_symlink():
            raise ValueError("Migration staging directory must not be a symlink")
        if legacy in available:
            volume = json.loads(run([*docker_command(), "volume", "inspect", legacy]).stdout)[0]
            labels = volume.get("Labels") or {}
            if (
                labels.get("com.docker.compose.project") != config.project
                or labels.get("com.docker.compose.volume") != logical
            ):
                raise ValueError("Foreign legacy storage volume: " + legacy)
            active = run([*docker_command(), "ps", "-q", "--filter", "volume=" + legacy]).stdout
            if active.strip():
                raise ValueError("Stop containers using legacy storage before migrating: " + legacy)
            stage.mkdir(mode=0o700, exist_ok=True)
            print("Bestehende Daten in Bind-Mount übernehmen: " + logical, flush=True)
            helper(
                config,
                [
                    "type=volume,source=" + legacy + ",target=/legacy,readonly",
                    "type=bind,source=" + str(stage) + ",target=/target",
                ],
                "cp -a /legacy/. /target/",
            )
            stage.rename(target)
        else:
            if stage.exists():
                raise ValueError("Incomplete storage migration requires its original volume")
            stage.mkdir(mode=0o700)
            if logical == "cve_mailhog_data":
                helper(
                    config,
                    ["type=bind,source=" + str(stage) + ",target=/target"],
                    "chown 1000:1000 /target",
                )
            elif logical == "postgres_data":
                helper(
                    config,
                    ["type=bind,source=" + str(stage) + ",target=/target"],
                    "chown postgres:postgres /target",
                )
            elif logical == "cve_postfix_queue":
                # The upstream entrypoint recreates native queue directories and ownership.
                stage.chmod(0o755)
            stage.rename(target)


def remove(config: Config) -> None:
    """Delete only this project's bind data, including files owned by container users."""
    for base in dict.fromkeys(
        [directory(config), config.secrets_base / "storage" / config.project]
    ):
        remove_tree(config, base)


def remove_tree(config: Config, base: Path) -> None:
    if not base.exists():
        return
    from scripts.infrastructure.mounts import checked as checked_path

    checked_path(base)
    helper(
        config,
        ["type=bind,source=" + str(base) + ",target=/target"],
        "find /target -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; "
        f"chown {os.getuid()}:{os.getgid()} /target; chmod 700 /target",
    )
    base.rmdir()
