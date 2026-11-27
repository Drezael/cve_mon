"""Idempotent dual-key rotation of unattended personal-vault envelopes."""

import argparse
import fcntl
import json
import os
import re
import secrets
import tempfile
from pathlib import Path
from typing import Any

from cve_common.config.secrets import read_secret
from cve_common.user_vault import UserVaultKeyring, seal

from scripts.automation_executor.manage import prepare, prepare_keyring
from scripts.database import manage as db
from scripts.infrastructure.manage import Config, load_config
from scripts.security.manage import private_write


def write(path: Path, value: dict[str, Any]) -> None:
    fd, name = tempfile.mkstemp(prefix=".ssh-keyring-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        Path(name).replace(path)
    finally:
        Path(name).unlink(missing_ok=True)


def stage(config: Config, key_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", key_id):
        raise ValueError("Invalid key ID")
    path = prepare_keyring(config)
    value = json.loads(read_secret(path).get_secret_value())
    if key_id not in value["keys"]:
        value["keys"][key_id] = secrets.token_hex(32)
    # Distribute the new decryption key before any writer can use its key ID.
    write(path, value)
    prepare(config)
    value["active"] = key_id
    write(path, value)
    # Executor starts afresh for each run; API opens the master keyring on demand.
    prepare(config)


def rewrap(config: Config, *, batch_size: int = 100) -> dict[str, int]:
    ring = UserVaultKeyring(prepare_keyring(config))
    total = 0
    while True:
        with db.connect(config, "cve_migrator") as session:
            session.execute("SET ROLE postgres_owner")
            rows = session.execute(
                "SELECT user_id,key_id,runtime_envelope FROM security.ansible_vaults "
                "WHERE key_id<>%s ORDER BY user_id LIMIT %s FOR UPDATE",
                (ring.active, batch_size),
            ).fetchall()
            for row in rows:
                owner = row["user_id"]
                key = ring.runtime_key(owner, row)
                wrapped = seal(ring.keys[ring.active], key, b"cve:vault:runtime:v1:" + owner.bytes)
                assert (
                    ring.runtime_key(owner, {"key_id": ring.active, "runtime_envelope": wrapped})
                    == key
                )
                session.execute(
                    "UPDATE security.ansible_vaults SET key_id=%s,runtime_envelope=%s "
                    "WHERE user_id=%s",
                    (ring.active, wrapped, owner),
                )
            total += len(rows)
        print(json.dumps({"rewrapped": total}), flush=True)
        if len(rows) < batch_size:
            return verify(config)


def verify(config: Config) -> dict[str, int]:
    ring = UserVaultKeyring(prepare_keyring(config))
    total = 0
    with db.connect(config, "cve_migrator") as session:
        session.execute("SET ROLE postgres_owner")
        with session.cursor(name="verify_vaults") as cursor:
            cursor.execute(
                "SELECT user_id,key_id,runtime_envelope FROM security.ansible_vaults "
                "ORDER BY user_id"
            )
            for row in cursor:
                ring.runtime_key(row["user_id"], row)
                if row["key_id"] != ring.active:
                    raise ValueError("Old vault key references remain")
                total += 1
        legacy = session.execute(
            "SELECT count(*) AS n FROM inventory.ansible_profiles WHERE key_id<>'user-vault-v1'"
        ).fetchone()
        assert legacy is not None
        if legacy["n"]:
            raise ValueError("Legacy SSH profile key references remain")
    return {"verified": total}


def retire(config: Config, key_id: str, backup: Path) -> None:
    verify(config)
    path = prepare_keyring(config)
    value = json.loads(read_secret(path).get_secret_value())
    if key_id == value["active"] or backup.resolve() == path.resolve():
        raise ValueError("Cannot retire active key or overwrite the live keyring")
    if key_id not in value["keys"]:
        return
    if not backup.exists():
        private_write(backup, json.dumps(value))
    archived = UserVaultKeyring(backup)
    if archived.keys.get(key_id) != bytes.fromhex(value["keys"][key_id]):
        raise ValueError("Archived keyring does not retain the retiring key")
    del value["keys"][key_id]
    write(path, value)
    prepare(config)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["stage", "rewrap", "verify", "retire"])
    parser.add_argument("--key-id")
    parser.add_argument("--backup-keyring", type=Path)
    args = parser.parse_args()
    config = load_config()
    path = prepare_keyring(config)
    with path.with_suffix(".rotation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == "stage":
            if args.key_id is None:
                parser.error("--key-id required")
            stage(config, args.key_id)
        elif args.action == "retire":
            if args.key_id is None or args.backup_keyring is None:
                parser.error("--key-id and --backup-keyring required")
            retire(config, args.key_id, args.backup_keyring)
        else:
            print(json.dumps(rewrap(config) if args.action == "rewrap" else verify(config)))


if __name__ == "__main__":
    main()
