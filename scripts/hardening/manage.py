"""Reproducible Phase-23 entrypoints; invasive tests only use existing disposable fixtures."""

import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.hardening import supply_chain
from scripts.hardening.backup import transform
from scripts.repository_files import repository_files

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / ".runtime/test-reports"
SUITES = {
    "api": (["tests/services/api", "tests/hardening/test_http.py"], "security"),
    "auth": (["tests/authentication"], "authentication or security"),
    "rbac": (
        ["tests/authorization", "tests/server_administration"],
        "authorization or server_administration or security",
    ),
    "containers": (["tests/infrastructure"], "infrastructure or security"),
    "networks": (["tests/infrastructure/envoy", "tests/infrastructure/mail"], "egress or mail"),
    "database": (["tests/database"], "database"),
    "uploads": (
        ["tests/inventory_upload", "tests/inventory_processor"],
        "inventory_upload or inventory_processor or security",
    ),
    "pipelines": (
        [
            "tests/cve_importer",
            "tests/cve_enricher",
            "tests/matching",
            "tests/findings",
            "tests/notifications",
        ],
        "cve_importer or cve_enricher or matching or findings or notifications",
    ),
    "resilience": (["tests/automation", "tests/status"], "automation or status_integration"),
    "frontend": (
        ["tests/dashboard", "tests/dashboard_administration"],
        "dashboard or dashboard_administration",
    ),
    "hardening": (["tests/hardening"], "hardening or security"),
}
IMAGE_REGRESSIONS = [
    "api",
    "inventory",
    "importer",
    "enricher",
    "matching",
    "findings",
    "notification",
]
IMAGE_SUITES = {
    "api-image": (["tests/services/integration/test_container.py"], "services_integration"),
    "inventory-image": (["tests/inventory_processor/test_processing.py"], "inventory_processor"),
    "importer-image": (["tests/cve_importer/test_container.py"], "cve_importer"),
    "enricher-image": (["tests/cve_enricher/test_container.py"], "cve_enricher"),
    "matching-image": (["tests/matching/test_container.py"], "matching"),
    "findings-image": (["tests/findings/test_container.py"], "findings"),
    "notification-image": (["tests/notifications/test_container.py"], "notifications"),
}


def command(arguments: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(arguments, cwd=ROOT, check=True, env=env)


def suite(name: str) -> None:
    paths, marker = SUITES[name] if name in SUITES else IMAGE_SUITES[name]
    REPORTS.mkdir(parents=True, exist_ok=True)
    # Shared Docker address pools are finite. One native suite per operator workspace
    # prevents false infrastructure failures from overlapping seven-zone laboratories.
    lock = ROOT / ".runtime/hardening/laboratory.lock"
    lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock.open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        command(
            [
                sys.executable,
                "-m",
                "pytest",
                *paths,
                "-m",
                marker,
                "--junitxml=" + str(REPORTS / ("phase-23-" + name + ".xml")),
            ]
        )


def provenance() -> None:
    """No environment variables, credentials or build directories enter the manifest."""
    paths = repository_files(ROOT)
    values = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    value: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "source_hashes": values,
        "scanner_version": supply_chain.VERSION,
        "scanner_distribution_sha256": supply_chain.ARCHIVE_SHA256,
        "publication": False,
        "signature": None,
        "scope": "local source digest manifest; not an authenticated SLSA attestation",
    }
    target = REPORTS / "phase-23-provenance.json"
    target.write_text(json.dumps(value, indent=2))
    target.chmod(0o600)


def acceptance() -> None:
    """Never turn missing evidence or unresolved image findings into a successful release."""
    import xml.etree.ElementTree as ET

    failures = []
    from scripts.hardening.components import policy_sha256

    components = REPORTS / "phase-23-components.json"
    inventory = supply_chain.REPORTS / "image-inventory.json"
    if not components.is_file() or not inventory.is_file():
        failures.append("missing embedded component verification")
    else:
        report = json.loads(components.read_text())
        if (
            report.get("passed") is not True
            or report.get("policy_sha256") != policy_sha256()
            or report.get("inventory_sha256") != hashlib.sha256(inventory.read_bytes()).hexdigest()
            or len(report.get("artifacts", [])) != 7
        ):
            failures.append("embedded component verification differs from current artifacts/policy")
        try:
            age = (datetime.now(UTC) - datetime.fromisoformat(report["checked_at"])).total_seconds()
            if not 0 <= age <= 86400:
                failures.append("stale embedded component verification")
        except (KeyError, ValueError):
            failures.append("missing embedded component verification timestamp")
    for name in [*SUITES, *(name + "-image" for name in IMAGE_REGRESSIONS)]:
        path = REPORTS / ("phase-23-" + name + ".xml")
        if not path.is_file():
            failures.append("missing suite: " + name)
            continue
        cases = list(ET.parse(path).iter("testcase"))
        if not cases or any(
            any(c.find(tag) is not None for tag in ["failure", "error", "skipped"]) for c in cases
        ):
            failures.append("incomplete/failed suite: " + name)
    for kind in ["image", "dependency"]:
        path = supply_chain.REPORTS / (kind + "-gate.json")
        if not path.is_file():
            failures.append("missing scan: " + kind)
        else:
            report = json.loads(path.read_text())
            if report.get("blocking_findings"):
                failures.append("unresolved scanner findings: " + kind)
            if report.get("input_hashes") != supply_chain.input_hashes():
                failures.append("scan source inputs changed: " + kind)
            try:
                age = (
                    datetime.now(UTC) - datetime.fromisoformat(report["checked_at"])
                ).total_seconds()
                if not 0 <= age <= 86400:
                    failures.append("stale scan: " + kind)
            except (KeyError, ValueError):
                failures.append("missing scan timestamp: " + kind)
    baseline = REPORTS / "phase-23-performance-before.json"
    after = REPORTS / "phase-23-performance-after.json"
    if not baseline.is_file() or not after.is_file():
        failures.append("missing performance comparison")
    if after.is_file() and any(
        r.get("api_errors") for r in json.loads(after.read_text())["levels"]
    ):
        failures.append("API errors under measured workload")
    if after.is_file():
        levels = json.loads(after.read_text())["levels"]
        if [v.get("added_servers") for v in levels] != [100, 1000, 10000]:
            failures.append("incomplete measured workload levels")
    required: dict[str, dict[str, object]] = {
        "live-verification": {
            "healthy_services": 7,
            "encrypted_credentials_and_workflows_unchanged": True,
            "foreign_container_ids_names_created_unchanged": True,
            "policies_unchanged": True,
            "bindings_match_owned_current_containers": True,
            "static_artifact_parity": True,
        },
        "recovery": {"restore_verified": True, "source_plaintext_removed": True},
        "artifact-verification": {"all_scanned_artifacts_running": True},
        "postgres-portability": {
            "existing_cluster_started": True,
            "application_fingerprints_equal": True,
            "unicode_unique_order_equal": True,
            "role_password_hashes_equal": True,
        },
    }
    for name, expected in required.items():
        path = REPORTS / ("phase-23-" + name + ".json")
        if not path.is_file():
            failures.append("missing verification: " + name)
        else:
            value = json.loads(path.read_text())
            if any(value.get(key) != wanted for key, wanted in expected.items()):
                failures.append("incomplete verification: " + name)
            if name == "artifact-verification":
                inventory = supply_chain.REPORTS / "image-inventory.json"
                if (
                    value.get("input_hashes") != supply_chain.input_hashes()
                    or value.get("inventory_sha256")
                    != hashlib.sha256(inventory.read_bytes()).hexdigest()
                    or len(value.get("verified_services", [])) != 7
                ):
                    failures.append("artifact verification differs from scan")
                age = (
                    datetime.now(UTC) - datetime.fromisoformat(value["checked_at"])
                ).total_seconds()
                if not 0 <= age <= 86400:
                    failures.append("stale artifact verification")
    value = {
        "checked_at": datetime.now(UTC).isoformat(),
        "decision": "NO_GO" if failures else "GO_TO_PHASE_24_REVIEW",
        "blocking": failures,
        "production_release": False,
    }
    (REPORTS / "phase-23-acceptance.json").write_text(json.dumps(value, indent=2))
    print(json.dumps(value))
    if failures:
        raise ValueError("Phase-23 acceptance requirements not satisfied")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            *SUITES,
            *IMAGE_SUITES,
            "dependencies",
            "images",
            "tools",
            "provenance",
            "baseline",
            "performance",
            "acceptance",
            "seal",
            "unseal",
        ],
    )
    parser.add_argument("--source", type=Path)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--key-file", type=Path)
    args = parser.parse_args()
    REPORTS.mkdir(parents=True, exist_ok=True)
    if args.action in SUITES or args.action in IMAGE_SUITES:
        suite(args.action)
    elif args.action in {"seal", "unseal"}:
        if not all([args.source, args.target, args.key_file]):
            parser.error("--source, --target and --key-file required")
        transform(args.source, args.target, args.key_file, decrypt=args.action == "unseal")
    elif args.action in {"baseline", "performance"}:
        env = {**os.environ, "HARDENING_STAGE": "before" if args.action == "baseline" else "after"}
        command(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/hardening/test_workload.py",
                "-m",
                "hardening",
                "--junitxml=" + str(REPORTS / ("phase-23-" + args.action + ".xml")),
            ],
            env=env,
        )
    elif args.action == "tools":
        from scripts.hardening.tools import install

        install()
    elif args.action == "dependencies":
        supply_chain.dependencies()
    elif args.action == "images":
        supply_chain.images()
    elif args.action == "provenance":
        provenance()
    else:
        acceptance()


if __name__ == "__main__":
    main()
