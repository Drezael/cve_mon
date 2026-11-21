"""Quiesced development migration from eight application containers to three profiles."""

import base64
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from cve_common.deployment import GROUPS, PORTS, SERVICES, VENDORS

from scripts.application.build import build
from scripts.database import manage as db
from scripts.deployment.contracts import Environment, atomic
from scripts.deployment.orchestration import start_runtime
from scripts.deployment.recovery import (
    DIRECTORIES,
    capture_configuration,
    verify_recovered_credentials,
)
from scripts.hardening.backup import transform
from scripts.infrastructure import mail
from scripts.infrastructure.manage import Config, compose, docker_command, run


def checksum(rows: Any) -> str:
    values = [json.dumps(row, sort_keys=True, default=str) for row in rows]
    return hashlib.sha256(json.dumps(sorted(values)).encode()).hexdigest()


def protected_identity(config: Config) -> dict[str, Any]:
    result: dict[str, Any] = {}
    with db.connect(config) as connection:
        result["passwords"] = checksum(
            connection.execute(
                "SELECT user_id,password_hash,credential_version FROM security.password_credentials"
            ).fetchall()
        )
        result["users"] = checksum(
            connection.execute("SELECT id,username,mfa_required FROM security.users").fetchall()
        )
        result["mfa"] = checksum(
            connection.execute("SELECT to_jsonb(t) FROM security.mfa_methods t").fetchall()
        )
        result["recovery_codes"] = checksum(
            connection.execute("SELECT to_jsonb(t) FROM security.recovery_codes t").fetchall()
        )
        count = connection.execute("SELECT count(*) n FROM security.users").fetchone()
        assert count is not None
        result["user_count"] = count["n"]

    with db.connect(config, database="n8n") as connection:
        result["n8n_credentials"] = checksum(
            connection.execute("SELECT id,data FROM public.credentials_entity").fetchall()
        )
        result["n8n_workflows"] = checksum(
            connection.execute(
                "SELECT id,name,nodes,connections FROM public.workflow_entity"
            ).fetchall()
        )
    return result


def migrate(config: Config) -> dict[str, Any]:
    if config.values["APP_ENV"] != "development":
        raise ValueError("Production migration requires an authorized release and recovery plan")
    ids = run(
        [
            *docker_command(),
            "ps",
            "-aq",
            "--filter",
            "label=com.docker.compose.project=" + config.project,
        ]
    ).stdout.split()
    if not ids:
        raise ValueError("Use application up for a fresh installation")
    containers = json.loads(run([*docker_command(), "inspect", *ids]).stdout)
    old = {item["Config"]["Labels"].get("com.docker.compose.service"): item for item in containers}
    if set(old) == set(SERVICES):
        if any(
            not v["State"]["Running"] or v["State"].get("Health", {}).get("Status") != "healthy"
            for v in containers
        ):
            raise ValueError("Use application up to recover the existing compact deployment")
        return {"already_compact": True}
    if len(containers) != 13 or set(old) != {*PORTS, *VENDORS}:
        raise ValueError("Expected exactly the existing thirteen-service development stack")
    if any(not v["State"]["Running"] for v in containers):
        raise ValueError(
            "Existing deployment must be running before its consistent migration backup"
        )
    build(config)
    destination = (
        config.root
        / ".runtime/consolidation"
        / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8])
    )
    destination.mkdir(parents=True, mode=0o700)
    key = config.secrets_base / "security" / ("consolidation-" + destination.name + ".key")
    key.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(base64.b64encode(os.urandom(32)))
    atomic(
        destination / "containers-before.json",
        [
            {
                "service": service,
                "id": item["Id"],
                "image": item["Image"],
                "reference": item["Config"]["Image"],
            }
            for service, item in old.items()
        ],
    )
    workers = [old[role]["Id"] for role in [*PORTS, "cve-n8n"]]
    run([*docker_command(), "stop", "--time", "20", *workers])
    before = protected_identity(config)
    atomic(destination / "identity-before.json", before)
    try:
        with tempfile.TemporaryDirectory(prefix="plaintext-", dir=destination) as temporary:
            plain = Path(temporary)
            atomic(plain / "old-containers.json", containers)
            db.backup(config, plain / "database-dumps")
            mail.backup(config, plain / "mail-queue")
            modes: dict[str, dict[str, Any]] = {}
            for name in DIRECTORIES:
                original = (
                    db.workdir(config)
                    if name == "database"
                    else config.secrets_base / name / config.project
                )
                if original.exists():
                    capture_configuration(original, plain / "configuration" / name, plain, modes)
            capture_configuration(
                Path(config.values["TLS_CERT_FILE"]).parent,
                plain / "configuration/ingress-pki",
                plain,
                modes,
            )
            encrypted = destination / "encrypted"
            encrypted.mkdir(mode=0o700)
            files: dict[str, str] = {}
            for source in sorted(plain.rglob("*")):
                if source.is_file():
                    source.chmod(0o600)
                    name = (
                        hashlib.sha256(str(source.relative_to(plain)).encode()).hexdigest() + ".enc"
                    )
                    transform(source, encrypted / name, key)
                    files[str(source.relative_to(plain))] = name
            if "configuration/n8n/config/encryption.key" not in files:
                raise ValueError("n8n encryption key must be included in the full backup")
            atomic(
                plain / "index.json",
                {
                    "files": files,
                    "configuration_modes": modes,
                    "project": config.project,
                    "configuration": config.values,
                    "rpo": "quiesced logical dumps; no PITR",
                    "checksums": {
                        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in encrypted.iterdir()
                    },
                },
            )
            transform(plain / "index.json", encrypted / "index.enc", key)
        atomic(
            destination / "backup-complete.json",
            {"encrypted": True, "separate_key": True, "plaintext_removed": True},
        )
        # Remove only the seven stopped code containers; preserve all data/configuration mounts.
        for role in set(PORTS) - {"cve-api"}:
            run([*docker_command(), "rm", old[role]["Id"]])
        from scripts.application.manage import prepare
        from scripts.services import manage as api

        prepare(config, "cve-processing")
        prepare(config, "cve-sources")
        api.prepare(config)
        target = Environment(destination / "environment.json", {"kind": "staging"}, config)
        start_runtime(target, config.root)
        if protected_identity(config) != before:
            raise ValueError("Protected user, MFA or n8n identities changed")
        credentials = verify_recovered_credentials(target)
        rows = [
            json.loads(s) for s in compose(config, ["ps", "--format", "json"]).stdout.splitlines()
        ]
        if {row["Service"] for row in rows} != set(SERVICES) or any(
            row.get("Health") != "healthy" for row in rows
        ):
            raise ValueError("All eight consolidated services must be healthy")
        applications = []
        for group in GROUPS:
            container = compose(config, ["ps", "-q", group]).stdout.strip()
            applications.append(
                run(
                    [*docker_command(), "inspect", "--format", "{{.Image}}", container]
                ).stdout.strip()
            )
        if len(set(applications)) != 1:
            raise ValueError("Three application profiles must use one identical image")
        result = {
            "healthy_services": 8,
            "application_containers": 3,
            "application_images": 1,
            "protected_identities_unchanged": True,
            "n8n_credentials_verified": credentials,
            "backup": str(destination),
            "completed_at": datetime.now(UTC).isoformat(),
        }
        atomic(destination / "migration-complete.json", result)
        return result
    except BaseException:
        atomic(
            destination / "recovery-required.json",
            {"backup_preserved": True, "volumes_deleted": False},
        )
        raise


if __name__ == "__main__":
    from scripts.infrastructure.manage import load_config

    print(json.dumps(migrate(load_config())))
