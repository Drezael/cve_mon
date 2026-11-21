"""Controlled service recovery, always using selected immutable artifacts and existing guards."""

from pathlib import Path
from typing import Any

from scripts.deployment.contracts import Environment, atomic
from scripts.deployment.orchestration import smoke, start_runtime
from scripts.deployment.preflight import check
from scripts.deployment.recovery import WORKERS
from scripts.deployment.release import verify
from scripts.deployment.state import authorize, lock, transition
from scripts.infrastructure.manage import compose


def restart(
    target: Environment,
    bundle: Path,
    *,
    approval: Path | None = None,
    staging_evidence: Path | None = None,
) -> dict[str, Any]:
    manifest = verify(bundle, current_source=True)
    authorize(target, manifest, approval, staging_evidence, action="restart-services")
    with lock(target):
        transition(target, manifest["release_id"], "planned", "controlled_restart")
        transition(target, manifest["release_id"], "preflight")
        try:
            check(target, bundle, prepared=True, database_probe=False)
        except Exception:
            transition(target, manifest["release_id"], "blocked", "restart_preflight_failed")
            raise
        transition(target, manifest["release_id"], "approved", "authorized_restart")
        transition(target, manifest["release_id"], "deploying")
        try:
            compose(target.config, ["stop", *WORKERS])
            compose(
                target.config,
                [
                    "up",
                    "-d",
                    "--no-deps",
                    "--no-recreate",
                    "--wait",
                    "--wait-timeout",
                    "90",
                    "cve-postgres",
                ],
            )
            start_runtime(target, bundle)
            transition(target, manifest["release_id"], "verifying")
            result = smoke(target, bundle)
            atomic(target.control / "restart-verification.json", result)
            transition(target, manifest["release_id"], "completed")
            return result
        except Exception:
            from scripts.deployment.state import journal

            current = journal(target)[-1]["state"]
            transition(
                target,
                manifest["release_id"],
                "rollback_required" if current == "verifying" else "recovery_required",
                "restart_failed",
            )
            raise
