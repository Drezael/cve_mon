"""Adversarial release, approval, journal and exclusion checks; no service mutations."""

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.deployment import orchestration, release, state
from scripts.deployment.contracts import Environment, atomic, canonical, digest, read
from scripts.infrastructure.manage import Config


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    result = tmp_path / "bundle"
    result.mkdir()
    for folder in ["source", "frontend", "evidence"]:
        (result / folder).mkdir()
    (result / "source/app.py").write_text("safe=True\n")
    (result / "frontend/index.html").write_text("<html></html>")
    (result / "evidence/tests.json").write_text('{"passed":true}')

    def checksum(p: Path) -> str:
        return hashlib.sha256(p.read_bytes()).hexdigest()

    files = {"app.py": checksum(result / "source/app.py")}
    services = [
        "api",
        "processing",
        "sources",
        "mail-relay",
        "n8n",
        "nginx",
        "postgres",
    ]
    value = {
        "schema_version": 1,
        "version": "0.24.0-rc.1",
        "configuration_schema": 1,
        "migration_target": "00031_hardening_list_projection",
        "source": {"git_commit": None, "clean": False, "sha256": digest(files), "files": files},
        "images": [
            {
                "service": "cve-" + s,
                "image_id": "sha256:"
                + hashlib.sha256(
                    ("application" if s in {"api", "processing", "sources"} else s).encode()
                ).hexdigest(),
                "config_digests": [],
                "source_reference": "cve-application:candidate"
                if s in {"api", "processing", "sources"}
                else "cve-" + s + ":candidate",
            }
            for s in services
        ],
        "frontend": {"index.html": checksum(result / "frontend/index.html")},
        "evidence": {"tests.json": checksum(result / "evidence/tests.json")},
        "production_eligible": False,
    }
    value["release_id"] = digest(value)
    atomic(result / "manifest.json", value)
    atomic(
        result / "build-record.json",
        {"release_id": value["release_id"], "created_at": datetime.now(UTC).isoformat()},
    )
    return result


@pytest.mark.parametrize("member", ["source/app.py", "frontend/index.html", "evidence/tests.json"])
def test_release_tampering_rejected(bundle: Path, member: str) -> None:
    release.verify(bundle)
    (bundle / member).write_text("tampered")
    with pytest.raises(ValueError, match="checksum"):
        release.verify(bundle)


def test_release_cannot_change_manifest_under_same_identity(bundle: Path) -> None:
    value = read(bundle / "manifest.json")
    value["production_eligible"] = True
    atomic(bundle / "manifest.json", value)
    with pytest.raises(ValueError, match="identity"):
        release.verify(bundle)


def test_release_symlink_rejected(bundle: Path, tmp_path: Path) -> None:
    path = bundle / "source/app.py"
    data = path.read_bytes()
    path.unlink()
    other = tmp_path / "outside"
    other.write_bytes(data)
    path.symlink_to(other)
    with pytest.raises(ValueError, match="symlink"):
        release.verify(bundle)


@pytest.mark.parametrize("path", ["../outside", "/etc/passwd"])
def test_manifest_cannot_escape_bundle(bundle: Path, path: str) -> None:
    value = read(bundle / "manifest.json")
    value["source"]["files"] = {path: "0" * 64}
    value["release_id"] = digest({k: v for k, v in value.items() if k != "release_id"})
    atomic(bundle / "manifest.json", value)
    with pytest.raises(ValueError, match="Unsafe|Unexpected"):
        release.verify(bundle)


def test_duplicate_fields_rejected_without_echoing_secret(tmp_path: Path) -> None:
    path = tmp_path / "ambiguous"
    path.write_text('{"name":"first","name":"sensitive-value"}')
    with pytest.raises(ValueError, match="Duplicate") as exc:
        read(path)
    assert "sensitive-value" not in str(exc.value)


@pytest.fixture
def target(tmp_path: Path) -> Environment:
    config = Config(
        tmp_path, {"COMPOSE_PROJECT_NAME": "cve-db-test-phase24-unit123", "APP_ENV": "development"}
    )
    return Environment(tmp_path / "environment.json", {"kind": "staging", "name": "test"}, config)


def test_deployment_lock_excludes_second_operator(target: Environment) -> None:
    with state.lock(target), pytest.raises(ValueError, match="Another"), state.lock(target):
        pass
    with state.lock(target):
        pass


def test_state_field_is_not_production_authorization(target: Environment, bundle: Path) -> None:
    production = replace(target, contract={"kind": "production", "name": "test"})
    with pytest.raises(ValueError, match="committed"):
        state.authorize(production, release.verify(bundle), None, None)


def test_journal_detects_edits_and_forbids_skipping_preflight(target: Environment) -> None:
    with state.lock(target):
        state.transition(target, "r", "planned")
        with pytest.raises(ValueError, match="transition"):
            state.transition(target, "r", "completed")
        state.transition(target, "r", "preflight")
        state.transition(target, "r", "blocked", "unavailable")
    path = target.control / "journal.json"
    value = read(path)
    value["records"][0]["state"] = "approved"
    atomic(path, value)
    with pytest.raises(ValueError, match="integrity"):
        state.journal(target)


def test_dry_run_never_provisions_or_creates_journal(
    target: Environment, bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestration, "verify", lambda *a, **k: read(bundle / "manifest.json"))
    monkeypatch.setattr(orchestration, "check", lambda *a, **k: {"mode": "read_only"})
    assert orchestration.rollout(target, bundle, dry_run=True) == {"mode": "read_only"}
    assert not target.control.exists()


def test_production_signature_is_bound_to_environment_release_and_evidence(
    target: Environment, bundle: Path, tmp_path: Path
) -> None:
    key = Ed25519PrivateKey.generate()
    pub = tmp_path / "trusted.pub"
    pub.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    pub.chmod(0o644)
    production = replace(
        target,
        contract={"kind": "production", "name": "production", "approval_public_key_file": str(pub)},
    )
    manifest = release.verify(bundle)
    manifest["source"].update(clean=True, git_commit="a" * 40)
    manifest["production_eligible"] = True
    evidence = tmp_path / "staging.json"
    proof = {"release_id": manifest["release_id"], "accepted": True}
    atomic(evidence, proof)
    payload = {
        "release_id": manifest["release_id"],
        "environment": production.identity,
        "staging_sha256": digest(proof),
        "action": "deploy",
        "operator": "test-operator",
        "ticket": "TEST-ONLY",
        "expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
    }
    approval = tmp_path / "approval.json"

    def sign(value: dict[str, Any]) -> None:
        atomic(
            approval,
            {"payload": value, "signature": base64.b64encode(key.sign(canonical(value))).decode()},
        )

    sign(payload)
    state.authorize(production, manifest, approval, evidence)
    for field, value in [
        ("environment", "wrong"),
        ("release_id", "wrong"),
        ("staging_sha256", "wrong"),
        ("expires_at", (datetime.now(UTC) - timedelta(seconds=1)).isoformat()),
    ]:
        sign({**payload, field: value})
        with pytest.raises(ValueError):
            state.authorize(production, manifest, approval, evidence)
    sign(payload)
    other = Ed25519PrivateKey.generate()
    signed = read(approval)
    signed["signature"] = base64.b64encode(other.sign(canonical(payload))).decode()
    atomic(approval, signed)
    with pytest.raises(ValueError, match="signature"):
        state.authorize(production, manifest, approval, evidence)


def test_unlisted_source_cannot_be_smuggled_into_release(bundle: Path) -> None:
    (bundle / "source/extra.py").write_text("malicious=True")
    with pytest.raises(ValueError, match="Unexpected"):
        release.verify(bundle)


def test_duplicate_service_identities_rejected(bundle: Path) -> None:
    value = read(bundle / "manifest.json")
    value["images"] = [value["images"][0]] * 7
    value["release_id"] = digest({k: v for k, v in value.items() if k != "release_id"})
    atomic(bundle / "manifest.json", value)
    with pytest.raises(ValueError, match="Duplicate"):
        release.verify(bundle)


def test_public_approval_key_cannot_be_group_writable(
    target: Environment, bundle: Path, tmp_path: Path
) -> None:
    # Even a syntactically valid signed envelope may not select its own trust key.
    key = Ed25519PrivateKey.generate()
    pub = tmp_path / "trusted.pub"
    pub.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    pub.chmod(0o666)
    production = replace(
        target,
        contract={"kind": "production", "name": "test", "approval_public_key_file": str(pub)},
    )
    manifest = release.verify(bundle)
    manifest["production_eligible"] = True
    manifest["source"].update(clean=True, git_commit="a" * 40)
    proof = {"accepted": True, "release_id": manifest["release_id"]}
    evidence = tmp_path / "proof.json"
    atomic(evidence, proof)
    payload = {
        "release_id": manifest["release_id"],
        "environment": production.identity,
        "staging_sha256": digest(proof),
        "action": "deploy",
        "operator": "test",
        "ticket": "test",
        "expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
    }
    signed = tmp_path / "approval.json"
    atomic(
        signed,
        {"payload": payload, "signature": base64.b64encode(key.sign(canonical(payload))).decode()},
    )
    with pytest.raises(ValueError, match="writable"):
        state.authorize(production, manifest, signed, evidence)


def test_unlisted_directory_symlink_is_rejected(bundle: Path, tmp_path: Path) -> None:
    (bundle / "frontend/injected").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        release.verify(bundle)


def test_stopped_existing_deployment_is_not_treated_as_fresh(
    target: Environment,
    bundle: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    monkeypatch.setattr(orchestration, "verify", lambda *a, **k: read(bundle / "manifest.json"))
    calls: list[list[str]] = []

    def compose(config: object, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, "stopped-container", "")

    monkeypatch.setattr(orchestration, "compose", compose)
    monkeypatch.setattr(
        orchestration, "run", lambda a: subprocess.CompletedProcess(a, 0, "volume", "")
    )
    monkeypatch.setattr(orchestration, "check", lambda *a, **k: {"migration_current": None})
    with pytest.raises(ValueError, match="reachable verified schema"):
        orchestration.rollout(target, bundle)
    assert calls == [["ps", "--all", "-q"]]
    assert state.journal(target)[-1]["state"] == "blocked"


def test_production_prepare_only_validates_external_secrets(
    target: Environment,
    bundle: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production = replace(target, contract={"kind": "production", "name": "prod"})
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(orchestration, "check", lambda *a, **k: calls.append(k))
    from scripts.database import manage as db

    monkeypatch.setattr(db, "prepare", lambda *a: pytest.fail("secret generation"))
    monkeypatch.setattr(
        orchestration, "generate_certificates", lambda *a: pytest.fail("PKI generation")
    )
    orchestration.prepare(production, bundle)
    assert calls == [{"prepared": True, "database_probe": False}]


def test_production_configuration_cannot_bypass_authorization_by_relabeling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.deployment import contracts

    file = tmp_path / "environment.json"
    atomic(
        file,
        {
            "schema_version": 1,
            "name": "test-stage",
            "kind": "staging",
            "env_file": "platform.env",
            "minimum_free_bytes": 1073741824,
            "minimum_available_memory_bytes": 1073741824,
            "minimum_cpus": 1,
            "certificate_minimum_seconds": 60,
        },
    )
    cfg = Config(tmp_path, {"APP_ENV": "production"})
    monkeypatch.setattr(contracts, "load_config", lambda *a: cfg)
    with pytest.raises(ValueError, match="Non-production"):
        contracts.environment(file)
