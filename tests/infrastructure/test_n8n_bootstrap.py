"""Exercise actual pinned n8n imports against a disposable PostgreSQL container."""

import json
import os
import secrets
import shutil
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from scripts.infrastructure.images import REFERENCES
from scripts.infrastructure.manage import docker_command

pytestmark = pytest.mark.infrastructure


@pytest.fixture
def runtime(tmp_path: Path, repository_root: Path) -> Iterator[dict[str, Any]]:
    docker = docker_command()
    network = "cve-n8n-bootstrap-test-" + uuid4().hex[:12]
    database = network + "-postgres"
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    for name in ("database.password", "encryption.key"):
        target = private / name
        target.write_text(secrets.token_urlsafe(40))
        target.chmod(0o600)
    definitions = tmp_path / "workflows"
    shutil.copytree(repository_root / "workflows/n8n", definitions)
    credentials: dict[str, dict[str, Any]] = {}
    for source in definitions.glob("*.json"):
        for node in json.loads(source.read_text())["nodes"]:
            for kind, item in node.get("credentials", {}).items():
                credentials[item["id"]] = {
                    "id": item["id"],
                    "name": item["name"],
                    "type": kind,
                    "data": {"name": "X-CVE-Fixture", "value": "fixture-only"}
                    if kind == "httpHeaderAuth"
                    else {
                        "host": "unused",
                        "database": "unused",
                        "user": "unused",
                        "password": "fixture-only",  # pragma: allowlist secret
                    },
                }
    (private / "credentials.json").write_text(json.dumps(list(credentials.values())))
    (private / "credentials.json").chmod(0o600)
    subprocess.run([*docker, "network", "create", network], check=True, capture_output=True)
    try:
        subprocess.run(
            [
                *docker,
                "run",
                "-d",
                "--name",
                database,
                "--network",
                network,
                "--tmpfs",
                "/var/lib/postgresql:rw,nosuid,size=512m",
                "--mount",
                f"type=bind,source={private},target=/private,readonly",
                "-e",
                "POSTGRES_USER=n8n_app",
                "-e",
                "POSTGRES_DB=n8n",
                "-e",
                "POSTGRES_PASSWORD_FILE=/private/database.password",
                "-e",
                "POSTGRES_INITDB_ARGS=--locale=C",
                REFERENCES["postgres"],
            ],
            check=True,
            capture_output=True,
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            result = subprocess.run(
                [
                    *docker,
                    "exec",
                    database,
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    "n8n_app",
                    "-d",
                    "n8n",
                ],
                capture_output=True,
            )
            if result.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("Disposable PostgreSQL did not start")
        data = tmp_path / "data"
        data.mkdir(mode=0o700)
        command = [
            *docker,
            "run",
            "--rm",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--network",
            network,
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--mount",
            f"type=bind,source={data},target=/home/node/.n8n",
            "--mount",
            f"type=bind,source={private},target=/run/cve-n8n,readonly",
            "--mount",
            f"type=bind,source={definitions},target=/opt/cve-workflows,readonly",
            "--mount",
            f"type=bind,source={repository_root}/infrastructure/n8n,target=/opt/cve-n8n,readonly",
            "-e",
            "DB_TYPE=postgresdb",
            "-e",
            "DB_POSTGRESDB_HOST=" + database,
            "-e",
            "DB_POSTGRESDB_DATABASE=n8n",
            "-e",
            "DB_POSTGRESDB_USER=n8n_app",
            "-e",
            "DB_POSTGRESDB_PASSWORD_FILE=/run/cve-n8n/database.password",
            "-e",
            "N8N_ENCRYPTION_KEY_FILE=/run/cve-n8n/encryption.key",
            "-e",
            "N8N_DIAGNOSTICS_ENABLED=false",
            "--entrypoint",
            "node",
            REFERENCES["n8n"],
            "/opt/cve-n8n/bootstrap.cjs",
        ]
        yield {"command": command, "definitions": definitions, "database": database}
    finally:
        subprocess.run([*docker, "rm", "-f", database], capture_output=True, check=False)
        subprocess.run([*docker, "network", "rm", network], capture_output=True, check=False)


def snapshot(database: str) -> list[dict[str, Any]]:
    query = (
        "SELECT coalesce(json_agg(t),'[]'::json) FROM "
        '(SELECT id,name,nodes,connections,active,"versionId","activeVersionId" '
        "FROM workflow_entity ORDER BY id) t"
    )
    result = subprocess.run(
        [
            *docker_command(),
            "exec",
            database,
            "psql",
            "-U",
            "n8n_app",
            "-d",
            "n8n",
            "-Atqc",
            query,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return list(json.loads(result.stdout))


def bootstrap(runtime: dict[str, Any], *, success: bool = True) -> None:
    result = subprocess.run(runtime["command"], capture_output=True, text=True, timeout=150)
    if success:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Repository workflows synchronized and published" in result.stdout
    else:
        assert result.returncode != 0


def test_fresh_repeat_update_and_invalid_input(runtime: dict[str, Any]) -> None:
    directory = runtime["definitions"]
    # An initially imported extra workflow becomes unmanaged in subsequent starts.
    extra = json.loads((directory / "cve-control-status.json").read_text())
    extra.update(id="fixture-unmanaged", name="Keep this workflow")
    (directory / "fixture-extra.json").write_text(json.dumps(extra))
    bootstrap(runtime)
    first = snapshot(runtime["database"])
    assert len(first) == 18
    assert all(row["active"] and row["activeVersionId"] == row["versionId"] for row in first)
    (directory / "fixture-extra.json").unlink()
    target = directory / "cve-control-status.json"
    updated = json.loads(target.read_text())
    updated["name"] = "Updated repository workflow"
    target.write_text(json.dumps(updated))
    bootstrap(runtime)
    second = snapshot(runtime["database"])
    assert len(second) == len(first)
    assert next(row for row in second if row["id"] == updated["id"])["name"] == updated["name"]
    unmanaged = next(row for row in first if row["id"] == extra["id"])
    assert next(row for row in second if row["id"] == extra["id"]) == unmanaged
    bootstrap(runtime)
    third = snapshot(runtime["database"])
    assert len(third) == len(second)
    assert all(row["active"] and row["activeVersionId"] == row["versionId"] for row in third)
    target.write_text("{broken json")
    bootstrap(runtime, success=False)
    assert snapshot(runtime["database"]) == third
