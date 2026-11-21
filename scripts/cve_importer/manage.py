"""Private configuration, explicit imports and preserved Envoy bindings."""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psycopg
from cve_common.deployment import APPLICATION_IMAGE

from cve_importer.contracts import SOURCES, Configuration
from cve_importer.transport import private
from scripts.database import manage as db
from scripts.infrastructure import network as net
from scripts.infrastructure.manage import Config, compose, load_config

IMAGE = APPLICATION_IMAGE


def directory(config: Config) -> Path:
    return config.secrets_base / "cve-importer" / config.project


def prepare(config: Config) -> None:
    base = directory(config)
    if not config.manages_credentials and not base.exists():
        raise ValueError("External production credentials required")
    if base.is_symlink():
        raise ValueError("No symlink service directory")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, source in [
        ("importer.password", db.secret_file(config, "importer")),
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
    db.read_secret(base / "importer.password")
    sources = base / "sources.json"
    if sources.is_symlink():
        raise ValueError("No symlink configuration")
    if not sources.exists():
        if not config.manages_credentials:
            raise ValueError("External source configuration required")
        sources.write_text(Configuration().model_dump_json(indent=2) + "\n")
        sources.chmod(0o600)
    Configuration.model_validate_json(private(sources))
    if (base / "nvd.key").exists():
        from cve_common.config.secrets import read_secret

        read_secret(base / "nvd.key")
    scratch = config.mount_base / "cve-importer" / config.project / "scratch"
    if scratch.is_symlink():
        raise ValueError("No symlink scratch directory")
    scratch.mkdir(parents=True, mode=0o700, exist_ok=True)


def build(config: Config) -> None:
    from scripts.application.build import build as shared_build

    shared_build(config)


def start(config: Config) -> None:
    from scripts.application.manage import start as start_group

    start_group(config, "cve-processing")
    net.wait_client_ready(config, "cve-processing")


def enqueue(config: Config, source: str, mode: str, key: str) -> UUID:
    cfg = Configuration.model_validate_json(private(directory(config) / "sources.json"))
    if source not in cfg.enabled or source == "osv" and not cfg.osv_ecosystems:
        raise ValueError("Source/OSV streams require explicit configuration")
    with db.connect(config, "api_security") as connection:
        result = connection.execute(
            "SELECT cve.schedule_import(%s,%s,%s::jsonb,%s,%s) AS id",
            (source, mode, json.dumps({"configuration": cfg.model_dump()}), key, uuid4()),
        ).fetchone()
        assert result is not None
        return UUID(str(result["id"]))


def resume(config: Config, run_id: UUID) -> UUID:
    """Explicit fresh Phase-7 budget for a terminal job, retaining its pinned run/checkpoint."""
    with db.connect(config, "importer") as connection:
        row = connection.execute(
            "SELECT r.job_id FROM cve.import_runs r JOIN cve.source_leases l "
            "ON l.active_run=r.id JOIN automation.jobs j ON j.id=r.job_id "
            "WHERE r.id=%s AND j.status IN ('failed','timed_out','cancelled') "
            "AND r.status NOT IN ('completed','partial') FOR UPDATE OF l,r",
            (run_id,),
        ).fetchone()
        if row is None:
            raise ValueError("Only a terminal run with its original source lease can resume")
        with db.connect(config, "api_security") as controller:
            result = controller.execute(
                "SELECT automation.control_job(%s,'replay') AS id", (row["job_id"],)
            ).fetchone()
            assert result is not None
            job_id = UUID(str(result["id"]))
        connection.execute(
            "UPDATE cve.import_runs SET job_id=%s,status='planned',finished_at=NULL WHERE id=%s",
            (job_id, run_id),
        )
        return job_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            "prepare",
            "build",
            "up",
            "down",
            "enqueue",
            "resume",
            "sources",
            "runs",
            "records",
            "errors",
            "metrics",
            "permissions",
        ],
    )
    parser.add_argument("--source", choices=SOURCES)
    parser.add_argument(
        "--mode", choices=["initial", "incremental", "reconcile"], default="incremental"
    )
    parser.add_argument("--request-key", default=None)
    parser.add_argument("--run-id", type=UUID)
    args = parser.parse_args()
    try:
        config = load_config()
        if args.action == "prepare":
            prepare(config)
        elif args.action == "build":
            build(config)
        elif args.action == "up":
            start(config)
        elif args.action == "down":
            compose(config, ["stop", "cve-importer"])
        elif args.action == "resume":
            if not args.run_id:
                raise ValueError("Explicit terminal run required")
            print(json.dumps({"job_id": str(resume(config, args.run_id))}))
        elif args.action == "enqueue":
            if not args.source:
                raise ValueError("Explicit source required")
            print(
                json.dumps(
                    {
                        "run_id": str(
                            enqueue(
                                config, args.source, args.mode, args.request_key or str(uuid4())
                            )
                        )
                    }
                )
            )
        else:
            with db.connect(config, "importer") as c:
                c.execute("SET TRANSACTION READ ONLY")
                result: Any
                if args.action == "metrics":
                    result = c.execute("SELECT cve.importer_metrics()").fetchone()
                elif args.action == "sources":
                    result = c.execute(
                        "SELECT id,name,enabled,configuration_revision FROM cve.sources ORDER BY id"
                    ).fetchall()
                elif args.action == "runs":
                    result = c.execute(
                        "SELECT "
                        "id,source_id,mode,effective_status,read_count,new_count,changed_c"
                        "ount,unchanged_count,error_count,started_at,finished_at FROM "
                        "cve.import_run_status ORDER BY created_at DESC LIMIT 100"
                    ).fetchall()
                elif args.action == "errors":
                    result = c.execute(
                        "SELECT run_id,position,code FROM cve.import_errors WHERE "
                        "run_id=%s ORDER BY created_at LIMIT 100",
                        (args.run_id,),
                    ).fetchall()
                elif args.action == "permissions":
                    result = c.execute(
                        "SELECT n.nspname AS schema,c.relname AS object,"
                        "has_table_privilege(current_user,c.oid,'INSERT') AS can_insert,"
                        "has_table_privilege(current_user,c.oid,'UPDATE') AS can_update,"
                        "has_table_privilege(current_user,c.oid,'DELETE') AS can_delete "
                        "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
                        "ON n.oid=c.relnamespace WHERE (n.nspname,c.relname) IN "
                        "(('inventory','servers'),('inventory','server_groups'),"
                        "('inventory','snapshots'),('findings','findings'),"
                        "('security','user_server_access')) ORDER BY n.nspname,c.relname"
                    ).fetchall()
                else:
                    result = c.execute(
                        "SELECT "
                        "r.id,r.source_id,r.external_id,r.current_revision_id,r.present "
                        "FROM cve.source_records r ORDER BY r.source_id,r.external_id "
                        "LIMIT 100"
                    ).fetchall()
                print(json.dumps(result, default=str))
        return 0
    except (ValueError, OSError, psycopg.Error, subprocess.SubprocessError):
        print("Importer operation failed; inspect private diagnostics", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
