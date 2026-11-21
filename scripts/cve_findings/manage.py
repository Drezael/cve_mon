"""Explicit offline findings operations; only own labelled namespace and credentials."""

import argparse
import json
import shutil
from pathlib import Path
from uuid import uuid4

from cve_common.deployment import APPLICATION_IMAGE
from cve_findings.contracts import Request

from scripts.database import manage as db
from scripts.infrastructure import network as net
from scripts.infrastructure.manage import Config, compose, load_config

IMAGE = APPLICATION_IMAGE


def directory(config: Config) -> Path:
    return config.secrets_base / "cve-findings" / config.project


def prepare(config: Config) -> None:
    base = directory(config)
    if base.is_symlink():
        raise ValueError("Unsafe service directory")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, source in [
        ("findings_writer.password", db.secret_file(config, "findings_writer")),
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
    db.read_secret(base / "findings_writer.password")


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
            ("findings." + kind, payload.model_dump_json(), str(uuid4()), uuid4()),
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
            "consume_matching_event",
            "reconcile",
            "refresh_priority",
            "check_deadlines",
            "check_exceptions",
            "reevaluate",
            "backfill",
            "maintenance",
        ],
        default="reconcile",
    )
    parser.add_argument("--event")
    parser.add_argument("--result")
    parser.add_argument("--version", type=int)
    parser.add_argument("--identity")
    parser.add_argument("--finding")
    args = parser.parse_args()
    config = load_config()
    if args.action in {"prepare", "build", "up", "guard"}:
        {"prepare": prepare, "build": build, "up": start, "guard": guard}[args.action](config)
    elif args.action == "down":
        compose(config, ["stop", "cve-findings"])
    elif args.action == "enqueue":
        print(
            enqueue(
                config,
                args.kind,
                Request.model_validate(
                    {
                        "result_id": args.result,
                        "current_version": args.version,
                        "event_id": args.event,
                        "finding_id": args.finding,
                        "identity": args.identity,
                    }
                ),
            )
        )
    else:
        with db.connect(config, "findings_writer") as connection:
            sql = (
                "SELECT findings.metrics()"
                if args.action == "metrics"
                else (
                    "SELECT server_id,cve_id,status,current_priority FROM findings.curr"
                    "ent_findings LIMIT 100"
                )
            )
            print(json.dumps(connection.execute(sql).fetchall(), default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
