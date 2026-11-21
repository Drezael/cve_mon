"""Quiesced, authenticated full staging backup; restore never targets an existing database."""

import hashlib
import json
import shutil
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.database import manage as db
from scripts.deployment.contracts import Environment, atomic, digest, read
from scripts.deployment.orchestration import smoke, start_runtime
from scripts.deployment.release import verify
from scripts.deployment.state import lock
from scripts.hardening.backup import key_from_file, transform
from scripts.infrastructure import mail
from scripts.infrastructure.manage import compose

WORKERS = ["cve-api", "cve-processing", "cve-sources", "cve-n8n"]

DIRECTORIES = [
    "application",
    "ansible",
    "database",
    "services",
    "security",
    "authentication",
    "automation",
    "inventory-processor",
    "cve-importer",
    "cve-enricher",
    "cve-matcher",
    "cve-findings",
    "notifications",
    "n8n",
    "mail",
    "envoy",
    "nginx",
]


def snapshot(
    target: Environment,
    bundle: Path,
    destination: Path,
    key_file: Path,
    *,
    approval: Path | None = None,
    staging_evidence: Path | None = None,
) -> dict[str, Any]:
    from scripts.deployment.state import authorize

    authorize(
        target, verify(bundle, current_source=True), approval, staging_evidence, action="backup"
    )
    manifest = verify(bundle, current_source=True)
    if destination.exists():
        raise ValueError("New backup destination required")
    if key_file.resolve().is_relative_to(destination.resolve()):
        raise ValueError("Backup key must be separate")
    key_from_file(key_file)
    from scripts.automation_executor.agent import exclusive

    with lock(target), exclusive(target.config):
        smoke(target, bundle)
        destination.mkdir(parents=True, mode=0o700)
        from scripts.automation_executor.agent import generation, register_backup

        register_backup(target.config, destination, key_file)
        with tempfile.TemporaryDirectory(prefix="phase24-backup-", dir=target.control) as temporary:
            plain = Path(temporary)
            try:
                compose(target.config, ["stop", *WORKERS])
                db.backup(target.config, plain / "database-dumps")
                mail.backup(target.config, plain / "mail-queue")
                files: dict[str, str] = {}
                modes: dict[str, dict[str, Any]] = {}
                # Snapshot configuration, PKI, n8n key and credentials, never live database files.
                for directory in DIRECTORIES:
                    original = target.config.runtime_directory(directory)
                    if directory == "database":
                        original = db.workdir(target.config)
                    if not original.exists():
                        continue
                    capture_configuration(
                        original, plain / "configuration" / directory, plain, modes
                    )
                pki = Path(target.config.values["TLS_CERT_FILE"]).parent
                capture_configuration(pki, plain / "configuration/ingress-pki", plain, modes)
                for path in sorted(plain.rglob("*")):
                    if not path.is_file():
                        continue
                    path.chmod(0o600)
                    name = (
                        hashlib.sha256(str(path.relative_to(plain)).encode()).hexdigest() + ".enc"
                    )
                    transform(path, destination / name, key_file)
                    files[str(path.relative_to(plain))] = name
                if "configuration/n8n/config/encryption.key" not in files:
                    raise ValueError("n8n encryption key missing from backup")
                inventory = {
                    "schema_version": 1,
                    "erasure_generation": generation(target.config),
                    "release_id": manifest["release_id"],
                    "environment": target.identity,
                    "project": target.config.project,
                    "configuration": target.config.values,
                    "files": files,
                    "configuration_modes": modes,
                    "n8n_key_included": True,
                    "tls_and_secrets_included": True,
                    "postfix_quiesced": True,
                    "rpo": "quiesced logical dumps; no PITR",
                    "checksums": {
                        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in destination.iterdir()
                        if p.is_file()
                    },
                }
                index = plain / "index.json"
                atomic(index, inventory)
                transform(index, destination / "index.enc", key_file)
            finally:
                start_runtime(target, bundle)
        result = {
            "environment": target.identity,
            "release_id": manifest["release_id"],
            "backup_index_sha256": hashlib.sha256(
                (destination / "index.enc").read_bytes()
            ).hexdigest(),
            "backup_path": str(destination.resolve()),
            "created_at": datetime.now(UTC).isoformat(),
            "complete": True,
            "source_plaintext_removed": True,
        }
        atomic(target.control / "backup-verified.json", result)
        return result


def unpack(source: Path, key_file: Path, destination: Path) -> dict[str, Any]:
    if destination.exists():
        raise ValueError("Restore scratch directory must be new")
    destination.mkdir(mode=0o700, parents=True)
    transform(source / "index.enc", destination / "index.json", key_file, decrypt=True)
    value = read(destination / "index.json", private=True)
    for relative, name in value["files"].items():
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or Path(name).name != name:
            raise ValueError("Unsafe backup member")
        encrypted = source / name
        if (
            encrypted.is_symlink()
            or hashlib.sha256(encrypted.read_bytes()).hexdigest() != value["checksums"][name]
        ):
            raise ValueError("Backup checksum mismatch")
        output = destination / path
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        transform(encrypted, output, key_file, decrypt=True)
    return value


def restore_database_test(target: Environment, source: Path, key_file: Path) -> dict[str, Any]:
    """Existing role/catalog/fingerprint verifier always creates a new isolated recovery cluster."""
    with tempfile.TemporaryDirectory(prefix="phase24-restore-", dir=target.control) as temp:
        plain = Path(temp) / "decoded"
        inventory = unpack(source, key_file, plain)
        from scripts.automation_executor.agent import generation

        if inventory.get("erasure_generation", 0) < generation(target.config):
            raise ValueError("Backup predates permanent server erasure")
        if inventory["environment"] != target.identity:
            raise ValueError("Backup environment mismatch")
        for name in [
            "configuration/n8n/config/encryption.key",
            "configuration/notifications/service-key.current",
        ]:
            # Inclusion is also recorded through the complete encrypted inventory, not only a flag.
            if name not in inventory["files"]:
                raise ValueError("Recovery encryption/service key missing")
        result = db.restore_test(target.config, plain / "database-dumps")
        key_path = plain / "configuration/n8n/config/encryption.key"
        result.update(
            {
                "isolated_restore": True,
                "n8n_key_present": key_path.is_file(),
                "backup_inventory_sha256": digest(inventory),
                "production_overwrite": False,
            }
        )
        index_hash = hashlib.sha256((source / "index.enc").read_bytes()).hexdigest()
        result.update({"environment": target.identity, "backup_index_sha256": index_hash})
        atomic(target.control / "restore-verification.json", result)
        marker_path = target.control / "backup-verified.json"
        marker = read(marker_path, private=True)
        if marker["backup_index_sha256"] != index_hash or marker["environment"] != target.identity:
            raise ValueError("Backup verification belongs to a different snapshot")
        atomic(marker_path, {**marker, "isolated_restore_verified": True})
        return result


def recover_stage(
    original: Environment,
    target: Environment,
    bundle: Path,
    source: Path,
    key_file: Path,
    *,
    approval: Path | None = None,
    staging_evidence: Path | None = None,
) -> dict[str, Any]:
    """Restore both DBs, key material, configuration and queue into a new isolated full stack."""
    import time

    from scripts.deployment.orchestration import pinned, prepare_runtime
    from scripts.infrastructure.manage import docker_command, run

    if (original.kind, target.kind) not in {("staging", "staging"), ("production", "production")}:
        raise ValueError("Production backups must never be restored into ordinary staging")
    if target.kind == "production":
        from scripts.deployment.state import authorize

        backup_id = hashlib.sha256((source / "index.enc").read_bytes()).hexdigest()
        action = "recover:" + original.identity + ":" + backup_id
        authorize(
            target, verify(bundle, current_source=True), approval, staging_evidence, action=action
        )
    if original.config.project == target.config.project:
        raise ValueError("Recovery must use a different project")
    manifest = verify(bundle, current_source=True)
    if compose(target.config, ["ps", "--all", "-q"]).stdout.strip():
        raise ValueError("Recovery target must have no containers")
    volumes = run(
        [
            *docker_command(),
            "volume",
            "ls",
            "--filter",
            "label=com.docker.compose.project=" + target.config.project,
            "--format",
            "{{.Name}}",
        ]
    ).stdout
    if volumes.strip():
        raise ValueError("Recovery target must have no persistent volumes")
    from scripts.infrastructure.storage import directory as storage_directory

    if storage_directory(target.config).exists():
        raise ValueError("Recovery target must have no persistent bind data")
    began = time.monotonic()
    with (
        lock(target),
        tempfile.TemporaryDirectory(prefix="phase24-full-restore-", dir=target.control) as temp,
    ):
        plain = Path(temp) / "decoded"
        inventory = unpack(source, key_file, plain)
        from scripts.automation_executor.agent import generation

        if inventory.get("erasure_generation", 0) < generation(target.config):
            raise ValueError("Backup predates permanent server erasure")
        if (
            inventory["environment"] != original.identity
            or inventory["release_id"] != manifest["release_id"]
        ):
            raise ValueError("Backup is not bound to the selected origin and release")
        if "configuration_modes" not in inventory:
            raise ValueError("Full recovery requires original configuration permission metadata")
        restore_configuration_modes(plain, inventory["configuration_modes"])
        cfg = target.config
        for directory in DIRECTORIES:
            extracted = plain / "configuration" / directory
            if not extracted.exists():
                continue
            destination = cfg.runtime_directory(directory)
            if directory == "database":
                destination = db.workdir(cfg)
            if destination.exists():
                raise ValueError("Recovery refuses existing configuration")
            shutil.copytree(extracted, destination)
        pki = Path(cfg.values["TLS_CERT_FILE"]).parent
        if pki.exists():
            raise ValueError("Recovery refuses existing ingress PKI")
        shutil.copytree(plain / "configuration/ingress-pki", pki)
        previous_pki = str(Path(inventory["configuration"]["TLS_CERT_FILE"]).parent)
        for issuer_config in pki.rglob("*.cnf"):
            issuer_config.write_text(issuer_config.read_text().replace(previous_pki, str(pki)))
            issuer_config.chmod(0o600)
        # No passwords/keys are regenerated: prepare() sees complete existing credentials.
        db.prepare(cfg)
        target = pinned(target, bundle)
        cfg = target.config
        compose(cfg, ["up", "-d", "--no-deps", "--wait", "--wait-timeout", "90", "cve-postgres"])
        db.provision(cfg)
        metadata = read(plain / "database-dumps/metadata.json", private=True)
        for database in db.DATABASES:
            db.pg_tool(
                cfg,
                [
                    "pg_restore",
                    "-h",
                    "/var/run/postgresql",
                    "-U",
                    "postgres_admin",
                    "--exit-on-error",
                    "-d",
                    database,
                ],
                input_file=plain / "database-dumps" / (database + ".dump"),
            )
            if db.fingerprint(cfg, database) != metadata["fingerprints"][database]:
                raise ValueError("Full recovery database fingerprint mismatch")
            from scripts.database.catalog import equivalent

            if not equivalent(
                database, db.catalog_metadata(cfg, database), metadata["catalogs"][database]
            ):
                raise ValueError("Full recovery database ownership/permission mismatch")
        if db.role_metadata(cfg) != metadata["roles"]:
            raise ValueError("Recovered role attributes differ")
        if "role_settings" not in metadata:
            raise ValueError("Full recovery requires role configuration metadata")
        db.restore_role_settings(cfg, metadata["role_settings"])
        db.verify(cfg)
        old_key = plain / "configuration/n8n/config/encryption.key"
        new_key = cfg.secrets_base / "n8n" / cfg.project / "config/encryption.key"
        if not old_key.is_file() or old_key.read_bytes() != new_key.read_bytes():
            raise ValueError("n8n encryption key was not preserved")
        prepare_runtime(target, bundle)
        compose(cfg, ["create", "--no-build", "cve-mail-relay"])
        mail.restore(cfg, plain / "mail-queue")
        start_runtime(target, bundle)
        result = smoke(target, bundle)
        result.update(
            {
                "full_service_restore": True,
                "database_fingerprints_equal_before_start": True,
                "database_catalogs_equal_before_start": True,
                "n8n_key_preserved": True,
                "postfix_queue_restored": True,
                "isolated": True,
                "production_overwrite": False,
                "elapsed_seconds": time.monotonic() - began,
                "rpo": "quiesced fixture snapshot",
                "rto": "measured local laboratory; not a production commitment",
            }
        )
        atomic(target.control / "full-recovery.json", result)
        return result


def verify_recovered_credentials(target: Environment) -> int:
    """Verify restored encrypted n8n credentials without exporting values to the host or logs."""
    from scripts.infrastructure.manage import compose, docker_command, run

    config = target.config
    directory = config.secrets_base / "notifications" / config.project
    wanted = {
        "cve-notification-service-v1": hashlib.sha256(
            (directory / "service-key.current").read_text().strip().encode()
        ).hexdigest(),
        "cve-notification-webhook-v1": hashlib.sha256(
            (directory / "webhook-key").read_text().strip().encode()
        ).hexdigest(),
    }
    program = """const fs=require('node:fs'),cp=require('node:child_process');
const crypto=require('node:crypto');
process.umask(0o077);const wanted=JSON.parse(fs.readFileSync(0,'utf8'));
const file='/tmp/phase24-credentials-'+crypto.randomUUID()+'.json';
try {
 const p=cp.spawnSync('n8n',['export:credentials','--all','--decrypted','--output='+file],
 {encoding:'utf8',maxBuffer:1048576});if(p.status!==0)throw Error('export failed');
 const rows=JSON.parse(fs.readFileSync(file,'utf8'));
 for(const [id,hash] of Object.entries(wanted)){
  const row=rows.find(v=>v.id===id);
  if(!row||typeof row.data.value!=='string'||
     crypto.createHash('sha256').update(row.data.value).digest('hex')!==hash)
    throw Error('credential verification failed');
 }
 console.log(JSON.stringify({verified:Object.keys(wanted).length}));
} finally {if(fs.existsSync(file))fs.unlinkSync(file);}
"""
    identity = compose(config, ["ps", "-q", "cve-n8n"]).stdout.strip()
    result = run(
        [*docker_command(), "exec", "-i", identity, "node", "-e", program], input=json.dumps(wanted)
    )
    value = json.loads(result.stdout)
    if value.get("verified") != 2:
        raise ValueError("Recovered n8n credentials did not verify")
    return 2


def require_verified_backup(target: Environment) -> None:
    """Fail before any service mutation when an existing deployment has no fresh tested backup."""
    marker = read(target.control / "backup-verified.json", private=True)
    proof = read(target.control / "restore-verification.json", private=True)
    age = (datetime.now(UTC) - datetime.fromisoformat(marker["created_at"])).total_seconds()
    index = Path(marker["backup_path"]) / "index.enc"
    if (
        marker.get("environment") != target.identity
        or marker.get("complete") is not True
        or marker.get("isolated_restore_verified") is not True
        or proof.get("isolated_restore") is not True
        or proof.get("environment") != target.identity
        or not 0 <= age <= 86400
        or index.is_symlink()
        or not index.is_file()
        or hashlib.sha256(index.read_bytes()).hexdigest() != marker["backup_index_sha256"]
        or proof.get("backup_index_sha256") != marker["backup_index_sha256"]
    ):
        raise ValueError("Fresh complete backup with matching isolated restore proof required")


def capture_configuration(
    source: Path,
    destination: Path,
    root: Path,
    modes: dict[str, dict[str, Any]],
) -> None:
    """Keep plaintext private while authenticating original runtime permissions in the index."""
    for path in [source, *source.rglob("*")]:
        if path.is_symlink():
            raise ValueError("Symlink in backup configuration")
        if path.name == "control.sock" and stat.S_ISSOCK(path.stat().st_mode):
            continue
        if not path.is_file() and not path.is_dir():
            raise ValueError("Regular backup configuration member required")
        if path.is_file() and path.suffix in {".dump", ".tar"}:
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & ~0o775:
            raise ValueError("Unsafe configuration permission cannot be restored")
        output = destination / path.relative_to(source)
        modes[str(output.relative_to(root))] = {"mode": mode, "directory": path.is_dir()}
        if path.is_dir():
            output.mkdir(parents=True, exist_ok=True, mode=0o700)
        else:
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(path, output)
            output.chmod(0o600)


def restore_configuration_modes(root: Path, modes: dict[str, Any]) -> None:
    """Only authenticated configuration members can regain their reviewed original modes."""
    checked: list[tuple[Path, int, bool]] = []
    for relative, item in modes.items():
        path = Path(relative)
        mode = item["mode"]
        directory = item["directory"]
        if (
            path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or path.parts[0] != "configuration"
            or type(mode) is not int
            or mode < 0
            or mode & ~0o775
            or type(directory) is not bool
        ):
            raise ValueError("Unsafe configuration permission metadata")
        target = root / path
        if any(p.is_symlink() for p in [target, *target.parents]):
            raise ValueError("Symlink in configuration restore")
        if (target.exists() and target.is_dir() != directory) or (
            not directory and not target.is_file()
        ):
            raise ValueError("Configuration permission member mismatch")
        checked.append((target, mode, directory))
    # Validate the complete inventory before changing any permission.
    for target, mode, directory in sorted(checked, key=lambda row: len(row[0].parts)):
        if directory:
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.chmod(mode)
