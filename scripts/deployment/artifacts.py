"""Portable offline Docker archives; no registry publication, service start or global pruning."""

import hashlib
import json
import os
import subprocess
import tarfile
from pathlib import Path
from typing import Any

from scripts.deployment.contracts import atomic, read
from scripts.deployment.release import verify
from scripts.infrastructure.manage import docker_command, run


def checksum(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def local_reference(item: dict[str, Any]) -> str:
    approved = [item["image_id"], *item["config_digests"]]
    for reference in approved:
        try:
            actual = run(
                [*docker_command(), "image", "inspect", "--format", "{{.Id}}", reference]
            ).stdout.strip()
        except subprocess.CalledProcessError:
            continue
        if actual in approved:
            return str(reference)
    raise ValueError("Approved immutable image is unavailable")


def archive_matches(path: Path, item: dict[str, Any]) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Regular Docker archive required")
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts or member.issym() or member.islnk():
                raise ValueError("Unsafe Docker archive member")
        stream = archive.extractfile("manifest.json")
        if stream is None:
            raise ValueError("Docker export manifest missing")
        data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("Docker manifest too large")
        manifests = json.loads(data)
        if not manifests:
            raise ValueError("Empty Docker export")
        for manifest in manifests:
            if any(tag != item["source_reference"] for tag in (manifest.get("RepoTags") or [])):
                raise ValueError("Archive would modify unrelated image tags")
            config = archive.extractfile(manifest["Config"])
            if config is None:
                raise ValueError("Docker image configuration missing")
            data = config.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024:
                raise ValueError("Docker configuration too large")
            if "sha256:" + hashlib.sha256(data).hexdigest() not in item["config_digests"]:
                raise ValueError("Docker configuration differs from scanned artifact")


def export(bundle: Path, directory: Path) -> dict[str, Any]:
    manifest = verify(bundle)
    if directory.exists():
        raise ValueError("New image export directory required")
    directory.mkdir(parents=True, mode=0o700)
    images = {}
    exported: dict[tuple[str, str], dict[str, Any]] = {}
    for item in manifest["images"]:
        key = (item["image_id"], item["source_reference"])
        if key in exported:
            images[item["service"]] = exported[key]
            continue
        reference = local_reference(item)
        file = directory / (item["service"] + ".tar")
        run([*docker_command(), "image", "save", "--output", str(file), reference])
        if os.environ.get("CVE_DOCKER_SUDO") == "1":
            run(["sudo", "-n", "chown", str(os.getuid()) + ":" + str(os.getgid()), str(file)])
        file.chmod(0o600)
        archive_matches(file, item)
        images[item["service"]] = {
            "file": file.name,
            "sha256": checksum(file),
            "bytes": file.stat().st_size,
        }
        exported[key] = images[item["service"]]
    result = {"schema_version": 1, "release_id": manifest["release_id"], "images": images}
    atomic(directory / "index.json", result, exclusive=True)
    return result


def import_images(bundle: Path, directory: Path) -> None:
    manifest = verify(bundle)
    index = read(directory / "index.json", private=True)
    wanted = {item["service"]: item for item in manifest["images"]}
    if index["release_id"] != manifest["release_id"] or set(index["images"]) != set(wanted):
        raise ValueError("Image export belongs to a different release")
    # Validate every archive before allowing Docker to import any of them.
    for name, value in index["images"].items():
        if Path(value["file"]).name != value["file"]:
            raise ValueError("Unsafe image export path")
        path = directory / value["file"]
        if checksum(path) != value["sha256"]:
            raise ValueError("Image archive checksum mismatch")
        archive_matches(path, wanted[name])
    loaded: set[str] = set()
    for value in index["images"].values():
        if value["file"] in loaded:
            continue
        loaded.add(value["file"])
        run([*docker_command(), "image", "load", "--input", str(directory / value["file"])])
    for item in wanted.values():
        local_reference(item)
