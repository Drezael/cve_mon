"""Consolidate actual Phase-24 evidence, preserving formal release and production gates."""

import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.deployment.contracts import ROOT, atomic, read
from scripts.deployment.release import fresh, verify
from scripts.hardening import supply_chain

REPORTS = ROOT / ".runtime/test-reports"
PROOFS = {
    "phase-24-native-stage.json": [
        "core_pinned_services",
        "read_only_preflight",
        "idempotent_rollout",
    ],
    "phase-24-business-chain.json": [
        "real_technical_ansible_upload",
        "real_dashboard_mfa_upload",
        "controlled_import_enrichment_matching",
        "actual_finding_event",
        "n8n_postfix_direct_test_delivery",
        "no_duplicate_submit",
    ],
    "phase-24-business-administration.json": [
        "triage_csrf_etag",
        "false_positive_reopening",
        "approved_resolution_recurrence",
        "exception_expiry_idempotent",
        "real_browser_administration",
    ],
    "phase-24-full-recovery.json": [
        "full_service_restore",
        "database_fingerprints_equal_before_start",
        "database_catalogs_equal_before_start",
        "n8n_key_preserved",
        "postfix_queue_restored",
    ],
    "phase-24-outage-exercise.json": ["inventory_preserved", "all_release_images_running"],
    "phase-24-offline-images.json": ["checksums_verified"],
}


def junit(path: Path, minimum: int) -> dict[str, int]:
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    failures = sum(len(list(root.iter(name))) for name in ["failure", "error", "skipped"])
    if failures or len(cases) < minimum:
        raise ValueError("Incomplete or unsuccessful mandatory test campaign")
    return {"tests": len(cases), "failures_errors_skips": failures}


def task_inventory(root: Path = ROOT) -> list[str]:
    """Load the release acceptance contract independently of private development plans."""
    document = read(root / "configuration/deployment/release/acceptance-tasks.json")
    tasks = document.get("task_ids")
    if (
        document.get("schema_version") != 1
        or not isinstance(tasks, list)
        or len(tasks) != 45
        or any(
            not isinstance(task, str) or not re.fullmatch(r"T24\.\d\d\.\d\d", task)
            for task in tasks
        )
        or len(set(tasks)) != 45
    ):
        raise ValueError("Incomplete task inventory")
    return sorted(str(task) for task in tasks)


def evaluate() -> dict[str, Any]:
    native = read(REPORTS / "phase-24-native-stage.json", private=True)
    bundle = Path(native["bundle"])
    manifest = verify(bundle, current_source=True)
    built_at = datetime.fromisoformat(read(bundle / "build-record.json")["created_at"]).timestamp()
    if not 0 <= datetime.now(UTC).timestamp() - built_at <= 86400:
        raise ValueError("Fresh staging campaign required")
    for name in [*PROOFS, "phase-24-native.xml"]:
        if (REPORTS / name).stat().st_mtime < built_at:
            raise ValueError("Stale staging evidence predates this installation")
    check_log = (REPORTS / "phase-24-check.log").read_text()
    if "Secret-Prüfung erfolgreich:" not in check_log or " failed" in check_log:
        raise ValueError("Complete repository quality campaign required")
    for name, required in PROOFS.items():
        proof = read(REPORTS / name, private=True)
        if proof.get("release_id") != manifest["release_id"] or any(
            proof.get(key) is not True for key in required
        ):
            raise ValueError("Mandatory proof missing or belongs to another release")
    if read(REPORTS / "phase-24-full-recovery.json")["credentials_decrypted_and_verified"] != 2:
        raise ValueError("Actual n8n credential recovery required")
    if read(REPORTS / "phase-24-offline-images.json")["exported_and_imported"] != 7:
        raise ValueError("Complete offline image transport required")
    tests = {
        "native": junit(REPORTS / "phase-24-native.xml", 15),
        "controls": junit(REPORTS / "phase-24-unit.xml", 50),
    }
    for kind in ["image", "dependency"]:
        gate = fresh(supply_chain.REPORTS / (kind + "-gate.json"))
        if gate["blocking_findings"] or gate["input_hashes"] != supply_chain.input_hashes():
            raise ValueError("Current zero-blocker security gates required")
    components = read(bundle / "evidence/phase-23-components.json")
    approved = {v["service"]: v["image_id"] for v in manifest["images"]}
    actual = {v["service"]: v["image_id"] for v in components["artifacts"]}
    if not components["passed"] or approved != actual:
        raise ValueError("Inherited component evidence differs from release images")
    old = read(bundle / "evidence/phase-23-test-summary.json")
    if any(old[key] != 0 for key in ["failures", "errors", "skipped"]):
        raise ValueError("Unsuccessful inherited regression evidence")
    formal = manifest["production_eligible"]
    tasks = task_inventory()
    gates = {"G24." + str(i): True for i in range(8)}
    gates["G24.1"] = formal
    gates.update({"G24.8": False, "G24.9": False})
    evidence = [*PROOFS, "phase-24-native.xml", "phase-24-unit.xml"]
    return {
        "checked_at": datetime.now(UTC).isoformat(),
        "release_id": manifest["release_id"],
        "source_sha256": manifest["source"]["sha256"],
        "git_commit": manifest["source"]["git_commit"],
        "technical_staging_accepted": True,
        "accepted": False,
        "formal_release_complete": formal,
        "production_release": False,
        "decision": "GO_TO_OPERATOR_REVIEW" if formal else "NO_GO_FORMAL_RELEASE_GIT_IDENTITY",
        "gates": gates,
        "tests": tests,
        "inherited_regressions": {
            "same_core_image_identities": True,
            "groups_overlap": True,
            "summary": old,
        },
        "task_status": {
            t: (
                "blocked"
                if not formal and t in {"T24.02.01", "T24.09.01", "T24.09.05"}
                else "completed"
            )
            for t in tasks
        },
        "evidence_sha256": {
            name: hashlib.sha256((REPORTS / name).read_bytes()).hexdigest() for name in evidence
        },
        "open_requirements": [
            *(
                []
                if formal
                else ["Explicitly authorized initial Git commit and formal release identity"]
            ),
            "Named production target, owner, PKI/secrets and capacity/RPO/RTO decisions",
            "Offsite/key-recovery and independent external monitoring acceptance",
            "Explicit independently signed production action; actual postdeployment verification",
        ],
    }


def main() -> None:
    try:
        result = evaluate()
    except Exception as error:
        atomic(
            REPORTS / "phase-24-acceptance.json",
            {
                "checked_at": datetime.now(UTC).isoformat(),
                "technical_staging_accepted": False,
                "accepted": False,
                "production_release": False,
                "decision": "NO_GO_TECHNICAL_EVIDENCE",
                "error_type": type(error).__name__,
            },
        )
        raise SystemExit(1) from None
    atomic(REPORTS / "phase-24-acceptance.json", result)
    print(result["decision"])


if __name__ == "__main__":
    main()
