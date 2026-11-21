"""Prepare dedicated status identity, public trust roots and sanitized adapter mounts."""

import os
import secrets
import shutil
from pathlib import Path

from scripts.database import manage as db
from scripts.infrastructure.manage import Config


def directory(config: Config) -> Path:
    return config.root / ".runtime/status" / config.project


def prepare(config: Config, target: Path) -> None:
    root = directory(config)
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    root.chmod(0o755)
    for name, uid in [("postfix", 0)]:
        # The API reads the same mutable adapter output through a nested read-only bind.
        (root / name).mkdir(exist_ok=True, mode=0o755)
        folder = config.mount_base / "status" / config.project / name
        folder.mkdir(parents=True, exist_ok=True, mode=0o755)
        if folder.is_symlink():
            raise ValueError("Adapter mount must be regular")
        if folder.stat().st_uid != uid:
            import subprocess

            subprocess.run(["sudo", "-n", "chown", str(uid), str(folder)], check=True)
    for source, name in [
        (db.secret_file(config, "status_probe"), "status_probe.password"),
        (Path(config.values["TLS_TRUST_FILE"]), "dashboard-ca.crt"),
    ]:
        if source.is_file():
            shutil.copyfile(source, target / name)
            (target / name).chmod(0o600)
    ca = config.secrets_base / "notifications" / config.project / "ca.crt"
    if ca.is_file():
        shutil.copyfile(ca, target / "notification-ca.crt")
        (target / "notification-ca.crt").chmod(0o644)
    probe = target / "status-probe.key"
    if not probe.exists():
        fd = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_urlsafe(32))
