"""Content-addressed local release candidates, verified source snapshots and immutable images."""

import hashlib
import json
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory

from scripts.deployment.contracts import ROOT, atomic, digest, read, schema
from scripts.hardening import supply_chain
from scripts.infrastructure.manage import docker_command, run
from scripts.repository_files import repository_files


def head(root: Path = ROOT) -> str:
    directory = ScriptDirectory.from_config(AlembicConfig(str(root / "database/alembic.ini")))
    heads = directory.get_heads()
    if len(heads) != 1:
        raise ValueError("Exactly one Alembic head required")
    return str(heads[0])


def source_identity(root: Path = ROOT) -> dict[str, Any]:
    files = {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in repository_files(root)
    }
    commit = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    changes = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return {
        "git_commit": commit.stdout.strip() if commit.returncode == 0 else None,
        "clean": not bool(changes.stdout.strip()),
        "sha256": digest(files),
        "files": files,
    }


def fresh(path: Path) -> dict[str, Any]:
    value = read(path)
    age = (datetime.now(UTC) - datetime.fromisoformat(value["checked_at"])).total_seconds()
    if not 0 <= age <= 86400:
        raise ValueError("Stale release evidence")
    return value


def create(version: str, output: Path, root: Path = ROOT) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?", version):
        raise ValueError("Semantic candidate version required")
    if output.exists():
        raise ValueError("Release destination must be new")
    from scripts.dashboard.provenance import verify as verify_dashboard

    verify_dashboard(root)
    from scripts.scan_secrets import scan

    if scan(root):
        raise ValueError("Source secret scan blocks release packaging")
    scans = supply_chain.REPORTS
    for kind in ["image", "dependency"]:
        gate = fresh(scans / (kind + "-gate.json"))
        if gate["blocking_findings"] or gate["input_hashes"] != supply_chain.input_hashes():
            raise ValueError("Current zero-blocker scan evidence required")
    inventory = json.loads((scans / "image-inventory.json").read_text())
    if len(inventory) != 7 or len({item["service"] for item in inventory}) != 7:
        raise ValueError("Complete seven-service inventory required")
    images = []
    for item in inventory:
        actual = run(
            [*docker_command(), "image", "inspect", "--format", "{{.Id}}", item["reference"]]
        ).stdout.strip()
        if actual != item["image_id"]:
            raise ValueError("Image tag differs from scanned artifact")
        images.append(
            {
                "service": item["service"],
                "image_id": actual,
                "config_digests": item["config_digests"],
                "source_reference": item["reference"],
            }
        )
    source = source_identity(root)
    dist = root / "services/dashboard/dist"
    if not (dist / "index.html").is_file():
        raise ValueError("Built frontend required")
    frontend = {
        str(p.relative_to(dist)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(dist.rglob("*"))
        if p.is_file()
    }
    evidence_files = (
        sorted(scans.glob("*.json"))
        + sorted((root / ".runtime/test-reports").glob("phase-23-*.xml"))
        + [
            root / ".runtime/test-reports" / name
            for name in [
                "phase-23-components.json",
                "phase-23-acceptance.json",
                "phase-23-recovery.json",
                "phase-23-postgres-portability.json",
                "phase-23-performance-after.json",
                "phase-23-test-summary.json",
            ]
        ]
    )
    evidence = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in evidence_files}
    value = {
        "schema_version": 1,
        "version": version,
        "configuration_schema": 1,
        "migration_target": head(root),
        "source": source,
        "images": sorted(images, key=lambda x: x["service"]),
        "frontend": frontend,
        "evidence": evidence,
        "production_eligible": source["clean"] and source["git_commit"] is not None,
    }
    value["release_id"] = digest(value)
    schema(value, "release/manifest.schema.json")
    output.mkdir(parents=True, mode=0o700)
    try:
        for directory in ["source", "frontend", "evidence"]:
            (output / directory).mkdir(mode=0o700)
        for relative in source["files"]:
            destination = output / "source" / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(root / relative, destination)
        shutil.copytree(dist, output / "frontend", dirs_exist_ok=True)
        for p in evidence_files:
            shutil.copyfile(p, output / "evidence" / p.name)
        atomic(output / "manifest.json", value, exclusive=True)
        atomic(
            output / "build-record.json",
            {"release_id": value["release_id"], "created_at": datetime.now(UTC).isoformat()},
            exclusive=True,
        )
    except Exception:
        atomic(output / "INCOMPLETE.json", {"complete": False})
        raise
    verify(output)
    return value


def verify(bundle: Path, *, current_source: bool = False) -> dict[str, Any]:
    value = read(bundle / "manifest.json")
    schema(value, "release/manifest.schema.json")
    body = {k: v for k, v in value.items() if k != "release_id"}
    if digest(body) != value["release_id"]:
        raise ValueError("Release identity mismatch")
    for section, values in [
        ("source", value["source"]["files"]),
        ("frontend", value["frontend"]),
        ("evidence", value["evidence"]),
    ]:
        base = bundle / section
        members = list(base.rglob("*"))
        if any(p.is_symlink() for p in members):
            raise ValueError("Unexpected symlink in release bundle")
        actual_members = {str(p.relative_to(base)) for p in members if p.is_file()}
        if actual_members != set(values):
            raise ValueError("Unexpected or missing release member")
        for relative, checksum in values.items():
            p = Path(relative)
            if p.is_absolute() or ".." in p.parts or not p.parts:
                raise ValueError("Unsafe release path")
            target = base / p
            if (
                any(parent.is_symlink() for parent in [target, *target.parents])
                or not target.is_file()
            ):
                raise ValueError("Release member missing or symlinked")
            if hashlib.sha256(target.read_bytes()).hexdigest() != checksum:
                raise ValueError("Release member checksum mismatch")
    if current_source:
        current = source_identity()
        if current["sha256"] != value["source"]["sha256"]:
            raise ValueError("Operator checkout differs from release source")
        if value["production_eligible"] and (
            not current["clean"] or current["git_commit"] != value["source"]["git_commit"]
        ):
            raise ValueError("Committed release provenance does not match checkout")
    if len({item["service"] for item in value["images"]}) != 7:
        raise ValueError("Duplicate release service identities")
    from cve_common.deployment import GROUPS, SERVICES

    if {item["service"] for item in value["images"]} != set(SERVICES):
        raise ValueError("Only the seven physical deployment services are allowed")
    applications = [item for item in value["images"] if item["service"] in GROUPS]
    if len({(item["image_id"], item["source_reference"]) for item in applications}) != 1:
        raise ValueError("All application profiles must share one immutable image")
    if digest(value["source"]["files"]) != value["source"]["sha256"]:
        raise ValueError("Source digest mismatch")
    record = read(bundle / "build-record.json", private=True)
    if record.get("release_id") != value["release_id"]:
        raise ValueError("Build record belongs to a different release")
    datetime.fromisoformat(record["created_at"])
    return value
