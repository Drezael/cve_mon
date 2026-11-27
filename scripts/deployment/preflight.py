"""Read-only release, host, TLS, secret, topology and migration preflight."""

import hashlib
import ipaddress
import json
import os
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

from scripts.database import manage as db
from scripts.deployment.contracts import Environment, read
from scripts.deployment.release import head, verify
from scripts.infrastructure.manage import (
    CERT_FILES,
    compose,
    docker_command,
    resolved,
    run,
    validate_model,
)


def topology(environment: Environment, manifest: dict[str, Any]) -> dict[str, Any]:
    base = resolved(replace(environment.config, compose_overrides=()))
    errors = validate_model(
        base,
        environment.config.values["APP_ENV"] == "development",
        environment.config.root,
        mount_base=environment.config.mount_base,
        secrets_base=environment.config.secrets_base,
    )
    if errors:
        raise ValueError("Base Compose policy validation failed")
    wanted = {item["service"]: item for item in manifest["images"]}
    if set(wanted) != set(base["services"]):
        raise ValueError("Release service inventory differs from Compose")
    effective = resolved(environment.config)
    for name, service in effective["services"].items():
        expected = dict(base["services"][name])
        approved = [wanted[name]["image_id"], *wanted[name]["config_digests"]]
        if service["image"] not in approved:
            raise ValueError("Unapproved immutable image in release overlay")
        expected["image"] = service["image"]
        if service != expected:
            raise ValueError("Release overlay changes more than approved images")
    return effective


def certificate(path: Path, seconds: int) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Certificate file missing")
    run(["openssl", "x509", "-in", str(path), "-noout", "-checkend", str(seconds)])
    return {"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def check(
    environment: Environment, bundle: Path, *, prepared: bool = True, database_probe: bool = True
) -> dict[str, Any]:
    manifest = verify(bundle, current_source=True)
    if manifest["migration_target"] != head():
        raise ValueError("Release migration target differs from checkout")
    model = topology(environment, manifest)
    images = []
    for item in manifest["images"]:
        actual = run(
            [
                *docker_command(),
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                model["services"][item["service"]]["image"],
            ]
        ).stdout.strip()
        if actual not in [item["image_id"], *item["config_digests"]]:
            raise ValueError("Immutable release image unavailable")
        images.append(item["service"])
    run([*docker_command(), "version", "--format", "{{.Server.Version}}"])
    run([*docker_command(), "compose", "version", "--short"])
    contract = environment.contract
    available = (
        int(
            next(
                line.split()[1]
                for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemAvailable:")
            )
        )
        * 1024
    )
    if (
        shutil.disk_usage(environment.config.root).free < contract["minimum_free_bytes"]
        or available < contract["minimum_available_memory_bytes"]
        or (os.cpu_count() or 0) < contract["minimum_cpus"]
    ):
        raise ValueError("Insufficient host resources")
    for service in model["services"].values():
        if not service.get("healthcheck") or service.get("privileged"):
            raise ValueError("Readiness and container bounds required")
        for port in service.get("ports", []):
            if (
                environment.kind != "production"
                and not ipaddress.ip_address(port["host_ip"]).is_loopback
            ):
                raise ValueError("Non-production public ingress forbidden")
    if prepared and environment.kind != "production":
        from scripts.infrastructure import mail

        if read(mail.directory(environment.config) / "state/policy.json")["enabled"]:
            raise ValueError("Staging SMTP must be disabled before rollout")
    certificates = []
    for name in CERT_FILES:
        path = Path(environment.config.values[name])
        if not path.is_absolute():
            path = environment.config.root / path
        if name.endswith("KEY_FILE"):
            if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
                raise ValueError("Private TLS key missing or unsafe")
        elif name != "CLIENT_CRL_FILE":
            certificates.append(certificate(path, contract["certificate_minimum_seconds"]))
    for role in ("postgres_admin", *db.LOGIN_ROLES):
        db.read_secret(db.secret_file(environment.config, role))
    if prepared:
        # Validate every bind source without printing paths/contents from operator credentials.
        for name, service in model["services"].items():
            for mount in service.get("volumes", []):
                if mount["type"] == "bind":
                    path = Path(mount["source"])
                    if path.is_symlink() or not path.exists():
                        raise ValueError(
                            "Required bind source missing: " + name + ":" + mount["target"]
                        )
                    if (
                        path.is_file()
                        and (path.suffix == ".key" or path.name.endswith(".password"))
                        and path.stat().st_mode & 0o077
                    ):
                        raise ValueError("Secret mount is not private")
    containers = compose(environment.config, ["ps", "--format", "json"]).stdout.splitlines()
    revision = None
    if database_probe and any(
        json.loads(line).get("Service") == "cve-postgres" for line in containers
    ):
        with db.connect(environment.config) as connection:
            exists = connection.execute(
                "SELECT to_regclass('public.alembic_version') AS v"
            ).fetchone()
            if exists and exists["v"]:
                rows = connection.execute(
                    "SELECT version_num FROM public.alembic_version"
                ).fetchall()
                if len(rows) != 1:
                    raise ValueError("Database migration branch ambiguity")
                revision = rows[0]["version_num"]
                if revision != manifest["migration_target"]:
                    from scripts.deployment.migrations import validate_plan

                    plan_file = environment.contract.get("migration_plan_file")
                    if not plan_file:
                        raise ValueError("Reviewed forward migration plan required")
                    path = Path(plan_file)
                    if not path.is_absolute():
                        path = environment.path.parent / path
                    validate_plan(
                        environment.config.root, path, revision, manifest["migration_target"]
                    )
    return {
        "passed": True,
        "release_id": manifest["release_id"],
        "environment": environment.identity,
        "services": images,
        "migration_current": revision,
        "migration_target": manifest["migration_target"],
        "certificates": certificates,
        "mode": "read_only",
        "prepared": prepared,
    }
