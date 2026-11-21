"""Run on the Docker host as an Ansible task. No target container is modified or executed."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_DOCUMENT = 40 * 1024 * 1024
MAX_EXPORT = 2 * 1024 * 1024 * 1024


def encode(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def run(argv: list[str], timeout: int = 300) -> str:
    # File-backed output avoids unbounded pipe memory, including hostile package metadata.
    with tempfile.TemporaryFile() as out:
        p = subprocess.run(
            ["/usr/bin/prlimit", "--fsize=" + str(MAX_EXPORT), "--core=0", "--", *argv],
            stdout=out,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        if p.returncode or out.tell() > MAX_DOCUMENT:
            raise ValueError("collection_failed")
        out.seek(0)
        return out.read(MAX_DOCUMENT + 1).decode()


def project(value: dict[str, Any], version: str) -> dict[str, Any]:
    """Allowlist software facts; Docker environment, commands and file contents never leave host."""
    packages: dict[str, dict[str, Any]] = {}
    for a in value.get("artifacts", []):
        if not a.get("name") or not a.get("version"):
            continue
        p = {"name": a["name"], "version": a["version"], "type": a.get("type", "unknown")}
        if a.get("purl"):
            p["purl"] = a["purl"]
        p["locations"] = sorted({loc["path"] for loc in a.get("locations", []) if loc.get("path")})[
            :32
        ]
        metadata = a.get("metadata") or {}
        for original, name in [
            ("source", "source_package"),
            ("sourceName", "source_package"),
            ("sourceVersion", "source_version"),
            ("architecture", "architecture"),
        ]:
            if isinstance(metadata.get(original), str) and metadata[original]:
                p[name] = metadata[original]
        if any(
            not isinstance(v, (str, list)) or isinstance(v, str) and (len(v) > 2048 or "\x00" in v)
            for v in p.values()
        ):
            raise ValueError("invalid_package")
        bounds = {
            "name": 512,
            "version": 512,
            "type": 64,
            "purl": 2048,
            "source_package": 512,
            "source_version": 512,
            "architecture": 128,
        }
        if any(len(p[k]) > maximum for k, maximum in bounds.items() if k in p):
            raise ValueError("package_field_limit")
        if any(len(location) > 1024 for location in p["locations"]):
            raise ValueError("package_location_limit")
        packages[encode(p)] = p
    if len(packages) > 20000:
        raise ValueError("package_limit")
    distro = value.get("distro") or {}
    return {
        "scanner": "syft",
        "scanner_version": version,
        "os": {
            k: distro[v]
            for k, v in [("id", "id"), ("version", "versionID"), ("name", "name")]
            if isinstance(distro.get(v), str) and distro[v]
        },
        "packages": [packages[k] for k in sorted(packages)],
    }


class Collector:
    def __init__(
        self, syft: str, docker: str, socket: str, cache: Path, mounts: list[str], workers: int = 2
    ) -> None:
        self.syft, self.docker, self.socket = syft, docker, socket
        self.cache, self.mounts, self.workers = cache, mounts, min(max(workers, 1), 2)
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        if cache.is_symlink() or cache.stat().st_uid != os.getuid() or cache.stat().st_mode & 0o077:
            raise ValueError("private_cache_required")
        self.version = run([syft, "version", "-o", "json"])
        self.version = json.loads(self.version)["version"]

    def docker_run(self, *args: str) -> str:
        return run([self.docker, "--host", self.socket, *args])

    def scan(self, target: str) -> dict[str, Any]:
        # No online enrichment or vulnerability feed: CVE matching stays in our monitor.
        return project(
            json.loads(
                run(
                    [
                        self.syft,
                        "scan",
                        target,
                        "--scope",
                        "squashed",
                        "--override-default-catalogers",
                        "image",
                        "-o",
                        "syft-json",
                        "-q",
                    ]
                )
            ),
            self.version,
        )

    def image(self, image: str) -> dict[str, Any]:
        key = hashlib.sha256(
            encode([image, self.version, "squashed-image-v2", self.socket]).encode()
        ).hexdigest()
        path = self.cache / (key + ".json")
        if path.exists() and not path.is_symlink():
            value = json.loads(path.read_text())
            if value.get("scanner_version") == self.version:
                return dict(value)
        # Explicit docker source and host prohibit an implicit registry pull.
        previous = os.environ.get("DOCKER_HOST")
        os.environ["DOCKER_HOST"] = self.socket
        try:
            value = self.scan("docker:" + image)
        finally:
            if previous is None:
                os.environ.pop("DOCKER_HOST", None)
            else:
                os.environ["DOCKER_HOST"] = previous
        with tempfile.NamedTemporaryFile(mode="w", dir=self.cache, delete=False) as out:
            out.write(encode(value))
            temporary = Path(out.name)
        temporary.replace(path)
        return value

    def collect(self, container: dict[str, Any], images: dict[str, Any]) -> list[dict[str, Any]]:
        cid, image = container["container_id"], container["image_id"]
        entries = []

        def entry(
            scope: str, document: Any = None, error: str | None = None, target: str | None = None
        ) -> None:
            e = {
                "container_id": cid,
                "image_id": image,
                "scope": scope,
                "status": "failed" if error else "complete",
                "captured_at": datetime.now(UTC).isoformat(),
            }
            if document is not None:
                e["document"] = document
            if error:
                e["error_code"] = error
            if target:
                e["target"] = target
            entries.append(e)

        if isinstance(images[image], dict):
            entry("image", images[image])
        else:
            entry("image", error="image_scan_failed")
        if container["state"] != "running":
            return entries
        try:
            if self.docker_run("container", "diff", cid).strip():
                with tempfile.TemporaryDirectory(dir=self.cache, prefix="runtime-") as directory:
                    archive = Path(directory) / "rootfs.tar"
                    subprocess.run(
                        [
                            "/usr/bin/prlimit",
                            "--fsize=" + str(MAX_EXPORT),
                            "--core=0",
                            "--",
                            self.docker,
                            "--host",
                            self.socket,
                            "container",
                            "export",
                            "--output",
                            str(archive),
                            cid,
                        ],
                        check=True,
                        timeout=300,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    unpacked = Path(directory) / "rootfs"
                    unpacked.mkdir()
                    total = count = 0
                    with tarfile.open(archive) as stream:
                        for member in stream:
                            path = Path(member.name)
                            if path.is_absolute() or ".." in path.parts:
                                raise ValueError("unsafe_archive_path")
                            if not member.isfile():
                                continue
                            count += 1
                            total += member.size
                            if count > 100000 or total > MAX_EXPORT:
                                raise ValueError("archive_limit")
                            destination = unpacked / path
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            incoming = stream.extractfile(member)
                            if incoming is not None:
                                with destination.open("wb") as outgoing:
                                    shutil.copyfileobj(incoming, outgoing)
                    entry("runtime", self.scan("dir:" + str(unpacked)))
        except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError):
            entry("runtime", error="runtime_scan_failed")
        try:
            mounts = json.loads(
                self.docker_run("container", "inspect", "--format", "{{json .Mounts}}", cid)
            )
            for mount in mounts or []:
                target = mount.get("Destination", "")
                # Explicit application paths only, never all host volumes or data directories.
                if target not in self.mounts:
                    continue
                source = mount.get("Source")
                try:
                    if not source or not (Path(source).is_dir() or Path(source).is_file()):
                        raise ValueError("mount_unavailable")
                    entry(
                        "mount",
                        self.scan(("dir:" if Path(source).is_dir() else "file:") + source),
                        target=target,
                    )
                except (ValueError, OSError, subprocess.SubprocessError):
                    entry("mount", error="mount_scan_failed", target=target)
        except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError):
            entry("mount", error="mount_inspection_failed", target="/")
        return entries

    def all(self) -> dict[str, Any]:
        ids = self.docker_run("container", "ls", "--all", "--quiet", "--no-trunc").split()
        if len(ids) > 10000 or any(not re.fullmatch(r"[0-9a-f]{64}", c) for c in ids):
            raise ValueError("container_limit")
        containers = []
        for cid in ids:
            c = json.loads(
                self.docker_run(
                    "container",
                    "inspect",
                    "--format",
                    '{"container_id":{{json .Id}},"image_id":{{json .Image}},"state":{{json '
                    ".State.Status}}}",
                    cid,
                )
            )
            containers.append(c)
        images: dict[str, Any] = {}
        for image in sorted({c["image_id"] for c in containers}):
            try:
                images[image] = self.image(image)
            except (ValueError, OSError, subprocess.SubprocessError):
                images[image] = None
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
            items = [
                e
                for group in pool.map(lambda c: self.collect(c, images), containers)
                for e in group
            ]
        return {
            "status": "partial" if any(e["status"] != "complete" for e in items) else "complete",
            "items": items,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syft", default="/usr/local/bin/syft")
    parser.add_argument("--docker", default="/usr/bin/docker")
    parser.add_argument("--socket", default="unix:///var/run/docker.sock")
    parser.add_argument("--cache", type=Path, default=Path("/var/cache/cve-monitoring/sbom"))
    parser.add_argument("--mounts", default="[]")
    args = parser.parse_args()
    try:
        mounts = json.loads(args.mounts)
        if not isinstance(mounts, list) or any(
            not isinstance(p, str)
            or not p.startswith("/")
            or p in {"/", "/etc", "/var", "/var/lib", "/run", "/proc", "/sys", "/dev"}
            for p in mounts
        ):
            raise ValueError("invalid_mount_paths")
        value = Collector(args.syft, args.docker, args.socket, args.cache, mounts).all()
    except (ValueError, OSError, subprocess.SubprocessError):
        value = {"status": "failed", "items": []}
    print(encode(value))


if __name__ == "__main__":
    main()
