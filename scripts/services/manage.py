"""Scoped API build/start/probes; existing PostgreSQL provisioning remains explicit."""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from cve_common.deployment import APPLICATION_IMAGE

from scripts.database import manage as database
from scripts.infrastructure.manage import Config, compose, docker_command, load_config, run

IMAGE = APPLICATION_IMAGE
PYTHON_IMAGE = "python@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7"


def directory(config: Config) -> Path:
    return config.secrets_base / "services" / config.project


def build(config: Config) -> None:
    from scripts.application.build import build as shared_build

    shared_build(config)


def prepare(config: Config) -> None:
    target = directory(config)
    if not config.manages_credentials and not target.exists():
        raise ValueError("Provision production API credential and CA externally")
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    from scripts.security.manage import prepare_auth
    from scripts.status.manage import prepare as prepare_status

    prepare_auth(config, target)
    from scripts.automation_executor.manage import prepare_keyring

    prepare_keyring(config)
    secret = target / "api_reader.password"
    if not secret.exists():
        source = database.secret_file(config, "api_reader")
        database.read_secret(source)
        shutil.copyfile(source, secret)
        secret.chmod(0o600)
    database.read_secret(secret)
    admin_secret = target / "dashboard_admin.password"
    if not admin_secret.exists() and config.manages_credentials:
        shutil.copyfile(database.secret_file(config, "dashboard_admin"), admin_secret)
        admin_secret.chmod(0o600)
    database.read_secret(admin_secret)
    from scripts.cve_importer.manage import directory as source_directory
    from scripts.cve_importer.manage import prepare as prepare_sources

    prepare_sources(config)
    # Copy only the nonsecret, validated source configuration into the API mount.
    shutil.copyfile(source_directory(config) / "sources.json", target / "import-sources.json")
    (target / "import-sources.json").chmod(0o600)
    prepare_status(config, target)
    from scripts.inventory.configuration import prepare as prepare_inventory

    prepare_inventory(config, target)
    ca = target / "ca.crt"
    if not ca.exists():
        shutil.copyfile(database.workdir(config) / "tls/ca.crt", ca)
    if (
        config.values["APP_ENV"] == "production"
        and (database.workdir(config) / "private/development.json").exists()
    ):
        raise ValueError("Production requires external database PKI")


def container(config: Config) -> dict[str, Any]:
    identifier = compose(config, ["ps", "-q", "cve-api"]).stdout.strip()
    if not identifier:
        raise ValueError("Own API not running")
    value = json.loads(run([*docker_command(), "inspect", identifier]).stdout)[0]
    if value["Config"]["Labels"].get("org.cve-monitoring.project") != config.project:
        raise ValueError("Foreign API container")
    return dict(value)


def probe(config: Config, path: str = "/health/ready") -> dict[str, Any]:
    if path not in {"/health/live", "/health/ready"}:
        raise ValueError("Technical probe only")
    code = (
        'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8000'
        + path
        + '", timeout=2).read().decode())'
    )
    return dict(
        json.loads(
            run([*docker_command(), "exec", container(config)["Id"], "python", "-c", code]).stdout
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["build", "prepare", "up", "down", "check", "smoke"])
    args = parser.parse_args()
    try:
        config = load_config()
        if args.action == "build":
            build(config)
        elif args.action == "prepare":
            prepare(config)
        elif args.action == "up":
            prepare(config)
            compose(config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-api"])
        elif args.action == "down":
            compose(config, ["stop", "cve-api"])
        else:
            probe(config, "/health/live")
            probe(config)
        print(json.dumps({"action": args.action, "project": config.project, "result": "ok"}))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(
            json.dumps({"action": args.action, "result": "error", "code": type(error).__name__}),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
