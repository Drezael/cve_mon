"""Project-scoped dispatcher build, private credentials, inspection and explicit controls."""

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
    return config.secrets_base / "automation" / config.project


def prepare(config: Config) -> None:
    base = directory(config)
    if not config.manages_credentials and not base.exists():
        raise ValueError("External production dispatcher files required")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, source in [
        ("event_dispatcher.password", db.secret_file(config, "event_dispatcher")),
        ("ca.crt", db.workdir(config) / "tls/ca.crt"),
    ]:
        target = base / name
        if target.is_symlink():
            raise ValueError("No symlink configuration")
        if not target.exists():
            shutil.copyfile(source, target)
            target.chmod(0o600)
    db.read_secret(base / "event_dispatcher.password")
    targets = base / "targets.json"
    if targets.is_symlink():
        raise ValueError("No symlink configuration")
    if not targets.exists():
        targets.write_text("[]\n")
        targets.chmod(0o600)
    if (
        config.values["APP_ENV"] == "production"
        and (db.workdir(config) / "private/development.json").exists()
    ):
        raise ValueError("Development PKI is not production PKI")


def build(config: Config) -> None:
    from scripts.application.build import build as shared_build

    shared_build(config)


def inspect(config: Config, kind: str) -> object:
    if kind not in {"jobs", "outbox"}:
        raise ValueError("Inspection type required")
    with db.connect(config, "reporter") as connection:
        row = connection.execute("SELECT automation.inspect_runtime(%s)", (kind,)).fetchone()
        assert row is not None
        return row["inspect_runtime"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            "build",
            "prepare",
            "up",
            "down",
            "jobs",
            "outbox",
            "check",
            "release",
            "cancel",
            "replay",
            "retry-delivery",
        ],
    )
    parser.add_argument("--job-id", type=UUID)
    parser.add_argument("--event-id", type=UUID)
    parser.add_argument("--destination")
    args = parser.parse_args()
    try:
        config = load_config()
        if args.action == "build":
            build(config)
        elif args.action == "prepare":
            prepare(config)
        elif args.action == "up":
            prepare(config)
            compose(config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-event-dispatcher"])
        elif args.action == "down":
            compose(config, ["stop", "cve-event-dispatcher"])
        elif args.action == "retry-delivery":
            if args.event_id is None or args.destination is None:
                raise ValueError("Explicit event and destination required")
            with db.connect(config, "api_security") as connection:
                assert connection.execute(
                    "SELECT automation.retry_delivery(%s,%s)", (args.event_id, args.destination)
                ).fetchone()
        elif args.action in {"release", "cancel", "replay"}:
            if args.job_id is None:
                raise ValueError("Explicit job ID required")
            with db.connect(config, "api_security") as connection:
                row = connection.execute(
                    "SELECT automation.control_job(%s,%s) AS id", (args.job_id, args.action)
                ).fetchone()
                assert row is not None
                print(json.dumps({"job_id": str(row["id"]), "operation": args.action}))
        elif args.action in {"jobs", "outbox"}:
            print(json.dumps(inspect(config, args.action)))
        else:
            with db.connect(config, "status_probe") as connection:
                assert connection.execute("SELECT automation.runtime_metrics()").fetchone()
        print(json.dumps({"action": args.action, "project": config.project, "result": "ok"}))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, psycopg.Error) as error:
        print(
            json.dumps({"action": args.action, "result": "error", "code": type(error).__name__}),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
