"""One cached, hash-locked image for all application profiles; no vendor rebuilds."""

import fcntl
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from scripts.infrastructure.manage import Config, docker_command, run
from scripts.infrastructure.topology import APPLICATION_IMAGE
from scripts.services.wheels import download_runtime

PACKAGES = [
    "packages/cve_common",
    *[
        "services/" + name
        for name in [
            "api",
            "event-dispatcher",
            "inventory",
            "importer",
            "enricher",
            "matcher",
            "findings",
            "notification",
            "automation",
        ]
    ],
]
LABEL = "org.cve-monitoring.application-inputs"


def fingerprint(root: Path) -> str:
    paths = [
        root / "requirements/runtime.txt",
        root / "LICENSE",
        root / "infrastructure/application/native-packages.lock.json",
        root / "scripts/application/native.py",
        root / "services/application/Dockerfile",
        Path(__file__),
    ]
    for name in PACKAGES:
        base = root / name
        paths.append(base / "pyproject.toml")
        paths.extend(
            p
            for p in (base / "src").rglob("*")
            if p.is_file()
            and "__pycache__" not in p.parts
            and not any(v.endswith(".egg-info") for v in p.parts)
        )
    digest = hashlib.sha256()
    digest.update(f"{os.getuid()}:{os.getgid()}".encode())
    for path in sorted(paths):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def build(config: Config) -> None:
    root = config.root
    context = root / ".runtime/application-image"
    context.mkdir(parents=True, exist_ok=True)
    with (context / "build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        digest = fingerprint(root)
        try:
            existing = run(
                [
                    *docker_command(),
                    "image",
                    "inspect",
                    "--format",
                    '{{index .Config.Labels "' + LABEL + '"}}',
                    APPLICATION_IMAGE,
                ]
            ).stdout.strip()
        except subprocess.CalledProcessError:
            existing = ""
        if existing == digest:
            return
        wheels = context / "wheels"
        if wheels.exists():
            shutil.rmtree(wheels)
        wheels.mkdir()
        download_runtime(root, wheels)
        from scripts.application.native import download

        download(root, context)
        with tempfile.TemporaryDirectory(prefix="cve-application-wheels-") as temporary:
            for name in PACKAGES:
                original = root / name
                clean = Path(temporary) / original.name
                clean.mkdir()
                shutil.copyfile(original / "pyproject.toml", clean / "pyproject.toml")
                shutil.copyfile(root / "LICENSE", clean / "LICENSE")
                shutil.copytree(
                    original / "src",
                    clean / "src",
                    ignore=shutil.ignore_patterns("*.egg-info", "__pycache__"),
                )
                run(
                    [
                        sys.executable,
                        "-m",
                        "pip",
                        "wheel",
                        "--no-deps",
                        "--no-build-isolation",
                        "--wheel-dir",
                        str(wheels),
                        str(clean),
                    ],
                    env={**os.environ, "SOURCE_DATE_EPOCH": "315532800"},
                )
        shutil.copyfile(root / "requirements/runtime.txt", context / "runtime.txt")
        shutil.copyfile(root / "services/application/Dockerfile", context / "Dockerfile")
        (context / "wheels.sha256").write_text(
            "".join(
                hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n"
                for path in sorted(wheels.glob("*.whl"))
            )
        )
        run(
            [
                *docker_command(),
                "build",
                "--network",
                "none",
                "--build-arg",
                "APPLICATION_UID=" + str(os.getuid()),
                "--build-arg",
                "APPLICATION_GID=" + str(os.getgid()),
                "--label",
                LABEL + "=" + digest,
                "--tag",
                APPLICATION_IMAGE,
                str(context),
            ]
        )
