"""Install the checksum-pinned Syft executable, without modifying a monitored image."""

import argparse
import hashlib
import io
import json
import platform
import tarfile
import urllib.request
from pathlib import Path


def install(destination: Path, *, arch: str | None = None) -> None:
    lock = json.loads(Path(__file__).with_name("syft.lock.json").read_text())
    arch = arch or {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    asset = lock["assets"]["linux_" + str(arch)]
    receipt = destination.with_suffix(".sha256")
    if (
        destination.is_file()
        and not destination.is_symlink()
        and receipt.is_file()
        and hashlib.sha256(destination.read_bytes()).hexdigest() == receipt.read_text().strip()
    ):
        return
    with urllib.request.urlopen(asset["url"], timeout=90) as response:
        raw = response.read(100 * 1024 * 1024 + 1)
    if len(raw) > 100 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != asset["sha256"]:
        raise ValueError("Syft release checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        member = archive.getmember("syft")
        if not member.isfile():
            raise ValueError("Executable missing from verified archive")
        stream = archive.extractfile(member)
        assert stream is not None
        binary = stream.read()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".new")
    temporary.write_bytes(binary)
    temporary.chmod(0o755)
    temporary.replace(destination)
    receipt.write_text(hashlib.sha256(binary).hexdigest() + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    install(parser.parse_args().destination)
