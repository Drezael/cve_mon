"""Ensure immutable upstream images are available; never rebuild vendor software.

The historical build/build_at entry points remain for existing deployment callers.
Only our application Dockerfiles build images, on the original Python base.
"""

import hashlib
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

from scripts.infrastructure.images import REFERENCES
from scripts.infrastructure.manage import Config, docker_command

IMAGES = {name: (reference, name) for name, reference in REFERENCES.items() if name != "envoy"}


def call(arguments: list[str], *, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=timeout)


def ensure(image: str) -> None:
    """Pull only when the exact immutable image is absent; preserve offline deployment."""
    try:
        call([*docker_command(), "image", "inspect", image])
    except subprocess.CalledProcessError:
        call([*docker_command(), "pull", image], timeout=900)


def build(config: Config, name: str) -> None:
    build_at(config.root, name)


def build_at(root: Path, name: str) -> None:
    ensure(IMAGES[name][0] if name in IMAGES else REFERENCES[name])


def fetch(url: str, checksum: str, target: Path) -> None:
    if target.is_symlink():
        raise ValueError("Artifact path must not be a symlink")
    if not target.exists():
        if urllib.parse.urlparse(url).scheme != "https":
            raise ValueError("HTTPS artifact required")
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(128 * 1024 * 1024 + 1)
        if len(data) > 128 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != checksum:
            raise ValueError("Artifact checksum/size mismatch: " + target.name)
        target.write_bytes(data)
    if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != checksum:
        raise ValueError("Cached artifact checksum mismatch")
    target.chmod(0o644)


if __name__ == "__main__":
    for runtime, (reference, _) in IMAGES.items():
        ensure(reference)
        print(runtime + ": original upstream image available", flush=True)
