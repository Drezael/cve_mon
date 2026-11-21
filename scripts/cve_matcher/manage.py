"""Explicit offline matcher operations; only own labelled namespace and credentials."""

import argparse
import json
import shutil
from pathlib import Path
from uuid import uuid4

from cve_common.deployment import APPLICATION_IMAGE
from cve_matcher.contracts import Request

from scripts.database import manage as db
from scripts.infrastructure import network as net
from scripts.infrastructure.manage import Config, compose, load_config

IMAGE = APPLICATION_IMAGE


def directory(config: Config) -> Path:
    return config.secrets_base / "cve-matcher" / config.project


def prepare(config: Config) -> None:
    base = directory(config)
    if base.is_symlink():
        raise ValueError("Unsafe service directory")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, source in [
        ("matcher.password", db.secret_file(config, "matcher")),
        ("ca.crt", db.workdir(config) / "tls/ca.crt"),
    ]:
        target = base / name
        if target.is_symlink():
            raise ValueError("Unsafe service configuration")
        if not target.exists():
            if not config.manages_credentials:
                raise ValueError("External production credentials required")
            shutil.copyfile(source, target)
            target.chmod(0o600)
    db.read_secret(base / "matcher.password")


def build(config: Config) -> None:
    from scripts.application.build import build as shared_build

    shared_build(config)


def guard(config: Config) -> None:
    from scripts.application.manage import processing_guard

    processing_guard(config)


def start(config: Config) -> None:
    from scripts.application.manage import start as start_group

    start_group(config, "cve-processing")
    net.wait_client_ready(config, "cve-processing")


def enqueue(config: Config, kind: str, payload: Request) -> str:
    with db.connect(config, "api_security") as connection:
        row = connection.execute(
            (
                "SELECT id FROM automation.enqueue_job(%s,1,%s::jsonb,%s,%s,0,NULL"
                ",NULL,3,'matching-operator',false)"
            ),
            ("matching." + kind, payload.model_dump_json(), str(uuid4()), uuid4()),
        ).fetchone()
        assert row is not None
        return str(row["id"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=["prepare", "build", "up", "down", "guard", "enqueue", "metrics", "current"],
    )
    parser.add_argument(
        "--kind",
        choices=[
            "evaluate_snapshot",
            "evaluate_vulnerability",
            "evaluate_candidate_batch",
            "reconcile",
            "backfill",
        ],
        default="reconcile",
    )
    parser.add_argument("--snapshot")
    parser.add_argument("--revision")
    parser.add_argument("--identity")
    args = parser.parse_args()
    config = load_config()
    if args.action in {"prepare", "build", "up", "guard"}:
        {"prepare": prepare, "build": build, "up": start, "guard": guard}[args.action](config)
    elif args.action == "down":
        compose(config, ["stop", "cve-matcher"])
    elif args.action == "enqueue":
        print(
            enqueue(
                config,
                args.kind,
                Request.model_validate(
                    {
                        "snapshot_id": args.snapshot,
                        "enrichment_revision_id": args.revision,
                        "identity": args.identity,
                    }
                ),
            )
        )
    else:
        with db.connect(config, "matcher") as connection:
            sql = (
                "SELECT matching.metrics()"
                if args.action == "metrics"
                else (
                    "SELECT server_id,identity,status,is_current FROM matching.current"
                    "_evaluations LIMIT 100"
                )
            )
            print(json.dumps(connection.execute(sql).fetchall(), default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
