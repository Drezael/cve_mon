"""Per-environment exclusion, hash-chained journals and independently signed authorizations."""

import base64
import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from scripts.deployment.contracts import Environment, atomic, canonical, digest, read

TRANSITIONS = {
    None: {"planned"},
    "planned": {"preflight"},
    "preflight": {"blocked", "approved"},
    "approved": {"deploying"},
    "deploying": {"verifying", "failed", "recovery_required"},
    "verifying": {"completed", "rollback_required", "failed"},
    "completed": {"planned"},
    "blocked": {"planned"},
    "failed": {"planned"},
    "rollback_required": {"planned"},
    "recovery_required": {"planned"},
}


@contextmanager
def lock(environment: Environment) -> Iterator[None]:
    directory = environment.control
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / "deployment.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another deployment owns this environment") from None
        yield
    finally:
        os.close(fd)


def journal(environment: Environment) -> list[dict[str, Any]]:
    path = environment.control / "journal.json"
    if not path.exists():
        return []
    value = read(path, private=True)
    records = value["records"]
    previous = "0" * 64
    for item in records:
        if (
            item["previous"] != previous
            or digest({k: v for k, v in item.items() if k != "sha256"}) != item["sha256"]
        ):
            raise ValueError("Deployment journal integrity failure")
        previous = item["sha256"]
    return list(records)


def transition(environment: Environment, release_id: str, state: str, reason: str = "") -> None:
    records = journal(environment)
    old = records[-1]["state"] if records else None
    if state not in TRANSITIONS.get(old, set()):
        raise ValueError("Invalid deployment state transition")
    record = {
        "state": state,
        "release_id": release_id,
        "environment": environment.identity,
        "at": datetime.now(UTC).isoformat(),
        "reason": reason,
        "previous": records[-1]["sha256"] if records else "0" * 64,
    }
    record["sha256"] = digest(record)
    atomic(environment.control / "journal.json", {"records": [*records, record]})


def authorize(
    environment: Environment,
    manifest: dict[str, Any],
    approval: Path | None,
    staging_evidence: Path | None,
    *,
    action: str = "deploy",
) -> None:
    if environment.kind != "production":
        return
    source = manifest["source"]
    if not manifest["production_eligible"] or not source["clean"] or source["git_commit"] is None:
        raise ValueError("Production requires a clean committed release")
    if approval is None or staging_evidence is None:
        raise ValueError("Independent production approval and staging evidence required")
    proof = read(staging_evidence, private=True)
    if proof.get("release_id") != manifest["release_id"] or proof.get("accepted") is not True:
        raise ValueError("Staging evidence does not authorize this release")
    signed = read(approval, private=True)
    if set(signed) != {"payload", "signature"}:
        raise ValueError("Invalid approval envelope")
    payload = signed["payload"]
    if set(payload) != {
        "release_id",
        "environment",
        "staging_sha256",
        "action",
        "expires_at",
        "operator",
        "ticket",
    }:
        raise ValueError("Invalid approval fields")
    if (
        payload["release_id"] != manifest["release_id"]
        or payload["environment"] != environment.identity
        or payload["staging_sha256"] != digest(proof)
        or payload["action"] != action
        or not payload["operator"]
        or not payload["ticket"]
    ):
        raise ValueError("Approval is not bound to this exact rollout")
    lifetime = (datetime.fromisoformat(payload["expires_at"]) - datetime.now(UTC)).total_seconds()
    if not 0 < lifetime <= 86400:
        raise ValueError("Expired or unbounded approval")
    keypath = Path(environment.contract["approval_public_key_file"])
    if not keypath.is_absolute():
        keypath = environment.path.parent / keypath
    if keypath.is_symlink() or not keypath.is_file():
        raise ValueError("Trusted approval key required")
    if keypath.stat().st_mode & 0o022 or keypath.stat().st_uid not in {0, os.getuid()}:
        raise ValueError("Approval trust key must not be writable by other users")
    key = load_pem_public_key(keypath.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Trusted Ed25519 approval key required")
    try:
        key.verify(base64.b64decode(signed["signature"], validate=True), canonical(payload))
    except Exception:
        raise ValueError("Production approval signature invalid") from None
