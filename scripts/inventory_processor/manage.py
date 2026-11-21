"""Build/start and metadata-only inventory inspection, without payload or credential output."""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import UUID

import psycopg
from cve_common.deployment import APPLICATION_IMAGE

from scripts.database import manage as db
from scripts.infrastructure.manage import Config, compose, load_config

IMAGE = APPLICATION_IMAGE


def directory(config: Config) -> Path:
    return config.secrets_base / "inventory-processor" / config.project


def prepare(config: Config) -> None:
    base = directory(config)
    if not config.manages_credentials and not base.exists():
        raise ValueError("External production inventory credentials required")
    if base.is_symlink():
        raise ValueError("No symlink service directory")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, source in [
        ("inventory_processor.password", db.secret_file(config, "inventory_processor")),
        ("ca.crt", db.workdir(config) / "tls/ca.crt"),
    ]:
        target = base / name
        if target.is_symlink():
            raise ValueError("No symlink configuration")
        if not target.exists():
            if not config.manages_credentials:
                raise ValueError("External production files required")
            shutil.copyfile(source, target)
            target.chmod(0o600)
    db.read_secret(base / "inventory_processor.password")
    if (
        config.values["APP_ENV"] == "production"
        and (db.workdir(config) / "private/development.json").exists()
    ):
        raise ValueError("Development PKI is not production PKI")


def build(config: Config) -> None:
    from scripts.application.build import build as shared_build

    shared_build(config)


def inspect(config: Config, action: str, identity: UUID | None = None) -> object:
    with db.connect(config, "inventory_processor") as c:
        if action == "backfill":
            return c.execute("SELECT inventory.backfill(100)").fetchone()
        c.execute("SET TRANSACTION READ ONLY")
        if action == "metrics":
            return c.execute("SELECT inventory.processor_metrics()").fetchone()
        if action == "submission":
            return c.execute(
                "SELECT * FROM inventory.processing_status WHERE submission_id=%s", (identity,)
            ).fetchone()
        if action == "snapshot":
            return c.execute(
                "SELECT * FROM inventory.matching_snapshots WHERE snapshot_id=%s", (identity,)
            ).fetchone()
        if action == "history":
            return c.execute(
                "SELECT * FROM inventory.matching_snapshots WHERE server_id=%s "
                "ORDER BY captured_at DESC,inventory_id DESC LIMIT 100",
                (identity,),
            ).fetchall()
        if action == "verify":
            return c.execute(
                "SELECT count(*) AS invalid FROM inventory.snapshots s WHERE "
                "s.submission_id IS NOT NULL AND "
                "(s.processing_status<>'processed' OR s.package_count<>(SELECT "
                "count(*) FROM inventory.packages p WHERE p.snapshot_id=s.id) OR "
                "s.service_count<>(SELECT count(*) FROM inventory.services p "
                "WHERE p.snapshot_id=s.id) OR s.container_count<>(SELECT count(*) "
                "FROM inventory.containers p WHERE p.snapshot_id=s.id) OR "
                "s.image_count<>(SELECT count(*) FROM inventory.images p WHERE "
                "p.snapshot_id=s.id))"
            ).fetchone()
        if action == "current":
            return c.execute(
                "SELECT server_id,snapshot_id FROM "
                "inventory.server_current_snapshots ORDER BY server_id LIMIT 100"
            ).fetchall()
        if action == "permissions":
            return c.execute(
                "SELECT "
                "has_table_privilege(current_user,'inventory.servers','UPDATE') "
                "AS "
                "server_write,has_table_privilege(current_user,'inventory.server_g"
                "roups','INSERT') AS "
                "group_write,has_table_privilege(current_user,'security.user_serve"
                "r_access','UPDATE') AS acl_write"
            ).fetchone()
        raise ValueError("Unknown operation")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            "build",
            "prepare",
            "up",
            "down",
            "backfill",
            "metrics",
            "submission",
            "snapshot",
            "history",
            "current",
            "permissions",
            "verify",
        ],
    )
    parser.add_argument("--id", type=UUID)
    args = parser.parse_args()
    try:
        config = load_config()
        if args.action in {"submission", "snapshot", "history"} and args.id is None:
            raise ValueError("Explicit identity required")
        if args.action == "build":
            build(config)
        elif args.action == "prepare":
            prepare(config)
        elif args.action == "up":
            prepare(config)
            compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-inventory"])
        elif args.action == "down":
            compose(config, ["stop", "cve-inventory"])
        else:
            print(json.dumps(inspect(config, args.action, args.id), default=str))
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError, psycopg.Error):
        print("Inventory operation failed; inspect private operator diagnostics", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
