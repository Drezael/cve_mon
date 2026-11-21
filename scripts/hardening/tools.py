"""Install the pinned audit tool into ignored operator storage and verify before execution."""

import hashlib
import os
import tarfile
import urllib.request
from pathlib import Path

from scripts.hardening.supply_chain import ARCHIVE_SHA256, VERSION, WORK, scanner


def install() -> Path:
    directory = WORK / "tools"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    archive = directory / "trivy.tar.gz"
    url = (
        f"https://github.com/aquasecurity/trivy/releases/download/v{VERSION}/"
        f"trivy_{VERSION}_Linux-64bit.tar.gz"
    )
    temporary = archive.with_suffix(".partial")
    try:
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as target:
            total = 0
            digest = hashlib.sha256()
            while chunk := response.read(65536):
                total += len(chunk)
                if total > 150 * 1024 * 1024:
                    raise ValueError("Scanner distribution exceeds budget")
                digest.update(chunk)
                target.write(chunk)
        if digest.hexdigest() != ARCHIVE_SHA256:
            raise ValueError("Scanner distribution checksum mismatch")
        temporary.chmod(0o600)
        os.replace(temporary, archive)
        with tarfile.open(archive) as source:
            member = source.getmember("trivy")
            data = source.extractfile(member)
            if not member.isfile() or member.size > 200 * 1024 * 1024 or data is None:
                raise ValueError("Invalid scanner distribution")
            executable = directory / "trivy"
            executable.write_bytes(data.read())
            executable.chmod(0o700)
        return scanner()
    finally:
        temporary.unlink(missing_ok=True)
