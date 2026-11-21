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
from cve_enricher.contracts import Configuration
from cve_enricher.files import private

from scripts.database import manage as db
from scripts.infrastructure import network as net
from scripts.infrastructure.manage import Config, compose, load_config

HOSTS = {"enricher": {"epss.empiricalsecurity.com"}}
IMAGE = APPLICATION_IMAGE


def directory(config: Config) -> Path:
    return config.secrets_base / "cve-enricher" / config.project


def prepare(config: Config) -> None:
    base = directory(config)
    if not config.manages_credentials and not base.exists():
        raise ValueError("External production credentials required")
    if base.is_symlink():
        raise ValueError("No symlink service directory")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, source in [
        ("enricher.password", db.secret_file(config, "enricher")),
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
    db.read_secret(base / "enricher.password")
    sources = base / "sources.json"
    if sources.is_symlink():
        raise ValueError("No symlink configuration")
    if not sources.exists():
        if not config.manages_credentials:
            raise ValueError("External source configuration required")
        sources.write_text(Configuration().model_dump_json(indent=2) + "\n")
        sources.chmod(0o600)
    Configuration.model_validate_json(private(sources))
    scratch = config.mount_base / "cve-enricher" / config.project / "scratch"
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


def enqueue(
    config: Config, kind: str, identity: str | None = None, score_date: str | None = None
) -> UUID:
    from cve_enricher.contracts import Request

    cfg = Configuration.model_validate_json(private(directory(config) / "sources.json"))
    if kind == "cve.epss.sync_daily" and not cfg.epss_enabled:
        raise ValueError("EPSS is disabled in the source configuration")
    payload = (
        Request.model_validate({"identity": identity, "score_date": score_date})
        if score_date
        else Request(identity=identity)
    )
    with db.connect(config, "api_security") as connection:
        row = connection.execute(
            "SELECT id FROM "
            "automation.enqueue_job(%s,1,%s::jsonb,%s,%s,0,NULL,NULL,3,'enrich"
            "er-operator',false)",
            (kind, payload.model_dump_json(), str(uuid4()), uuid4()),
        ).fetchone()
        assert row is not None
        return UUID(str(row["id"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=["prepare", "build", "up", "down", "enqueue", "metrics", "current", "epss"],
    )
    parser.add_argument(
        "--kind",
        choices=[
            "cve.enrich.record",
            "cve.enrich.backfill",
            "cve.enrich.reconcile",
            "cve.epss.sync_daily",
        ],
        default="cve.enrich.record",
    )
    parser.add_argument("--identity")
    parser.add_argument("--date")
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
            compose(config, ["stop", "cve-enricher"])
        elif args.action == "enqueue":
            print(json.dumps({"job_id": str(enqueue(config, args.kind, args.identity, args.date))}))
        else:
            result: Any
            with db.connect(config, "enricher") as connection:
                connection.execute("SET TRANSACTION READ ONLY")
                if args.action == "metrics":
                    result = connection.execute("SELECT cve.enricher_metrics()").fetchone()
                elif args.action == "epss":
                    result = connection.execute(
                        "SELECT r.* FROM cve.epss_current_dataset h JOIN "
                        "cve.epss_import_runs r ON r.id=h.dataset_id"
                    ).fetchall()
                else:
                    result = connection.execute(
                        "SELECT identity,id,rule_version,created_at FROM "
                        "cve.current_enrichment ORDER BY identity LIMIT 100"
                    ).fetchall()
                print(json.dumps(result, default=str))
        return 0
    except (ValueError, OSError, psycopg.Error, subprocess.SubprocessError):
        print("Importer operation failed; inspect private diagnostics", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
