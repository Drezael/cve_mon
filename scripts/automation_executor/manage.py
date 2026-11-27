"""Prepare dedicated SSH execution credentials for read-only inventory."""

import json
import os
import secrets
import shutil
import tempfile
from pathlib import Path

from cve_common.ssh_credentials import SSHKeyring

from scripts.database import manage as db
from scripts.infrastructure.manage import Config
from scripts.security.manage import private_write


def prepare_keyring(config: Config) -> Path:
    base = config.secrets_base / "services" / config.project
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = base / "ssh-keys.json"
    if not path.exists() and config.manages_credentials:
        private_write(path, json.dumps({"active": "1", "keys": {"1": secrets.token_hex(32)}}))
    SSHKeyring(path)
    return path


def prepare(config: Config) -> None:
    base = config.secrets_base / "ansible" / config.project
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    for source, name in [
        (prepare_keyring(config), "ssh-keys.json"),
        (db.secret_file(config, "ansible_worker"), "ansible_worker.password"),
        (db.workdir(config) / "tls/ca.crt", "ca.crt"),
    ]:
        target = base / name
        if target.is_symlink():
            raise ValueError("Symlink credential path denied")
        fd, temporary = tempfile.mkstemp(prefix=".credential-", dir=base)
        try:
            with os.fdopen(fd, "wb") as stream, source.open("rb") as original:
                shutil.copyfileobj(original, stream)
                stream.flush()
                os.fsync(stream.fileno())
            Path(temporary).replace(target)
        finally:
            Path(temporary).unlink(missing_ok=True)
