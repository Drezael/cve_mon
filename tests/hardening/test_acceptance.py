"""Release evidence must reject missing verification and unresolved image findings."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts.hardening import components, manage, supply_chain

pytestmark = pytest.mark.security


def test_acceptance_requires_deployment_and_recovery_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(manage, "REPORTS", tmp_path)
    monkeypatch.setattr(supply_chain, "REPORTS", tmp_path)
    monkeypatch.setattr(supply_chain, "input_hashes", lambda: {"fixture": "digest"})

    def write(name: str, value: object) -> None:
        (tmp_path / name).write_text(json.dumps(value))

    for name in [*manage.SUITES, *(name + "-image" for name in manage.IMAGE_REGRESSIONS)]:
        (tmp_path / f"phase-23-{name}.xml").write_text(
            '<testsuite><testcase classname="synthetic" name="pass"/></testsuite>'
        )
    for kind in ["image", "dependency"]:
        write(
            kind + "-gate.json",
            {
                "blocking_findings": [],
                "input_hashes": {"fixture": "digest"},
                "checked_at": datetime.now(UTC).isoformat(),
            },
        )
    performance = {"levels": [{"added_servers": v, "api_errors": 0} for v in [100, 1000, 10000]]}
    for stage in ["before", "after"]:
        write(f"phase-23-performance-{stage}.json", performance)
    with pytest.raises(ValueError):
        manage.acceptance()
    result = json.loads((tmp_path / "phase-23-acceptance.json").read_text())
    assert set(result["blocking"]) == {"missing embedded component verification"} | {
        "missing verification: " + name
        for name in [
            "live-verification",
            "recovery",
            "artifact-verification",
            "postgres-portability",
        ]
    }
    write(
        "phase-23-live-verification.json",
        {
            "healthy_services": 7,
            "encrypted_credentials_and_workflows_unchanged": True,
            "foreign_container_ids_names_created_unchanged": True,
            "policies_unchanged": True,
            "bindings_match_owned_current_containers": True,
            "static_artifact_parity": True,
        },
    )
    write("phase-23-recovery.json", {"restore_verified": True, "source_plaintext_removed": True})
    write(
        "phase-23-postgres-portability.json",
        {
            "existing_cluster_started": True,
            "application_fingerprints_equal": True,
            "unicode_unique_order_equal": True,
            "role_password_hashes_equal": True,
        },
    )
    write("image-inventory.json", [])
    component_report = {
        "passed": True,
        "policy_sha256": components.policy_sha256(),
        "inventory_sha256": hashlib.sha256(
            (tmp_path / "image-inventory.json").read_bytes()
        ).hexdigest(),
        "artifacts": [{} for _ in range(7)],
        "checked_at": datetime.now(UTC).isoformat(),
    }
    write("phase-23-components.json", component_report)
    write(
        "phase-23-artifact-verification.json",
        {
            "all_scanned_artifacts_running": True,
            "input_hashes": {"fixture": "digest"},
            "inventory_sha256": hashlib.sha256(
                (tmp_path / "image-inventory.json").read_bytes()
            ).hexdigest(),
            "verified_services": [{} for _ in range(7)],
            "checked_at": datetime.now(UTC).isoformat(),
        },
    )
    manage.acceptance()
    result = json.loads((tmp_path / "phase-23-acceptance.json").read_text())
    assert result["decision"] == "GO_TO_PHASE_24_REVIEW"
    path = tmp_path / "image-gate.json"
    report = json.loads(path.read_text())
    report["blocking_findings"] = [{"severity": "HIGH", "fixed": ""}]
    write(path.name, report)
    with pytest.raises(ValueError):
        manage.acceptance()
    result = json.loads((tmp_path / "phase-23-acceptance.json").read_text())
    assert result["blocking"] == ["unresolved scanner findings: image"]
    assert not result["production_release"]
    report["blocking_findings"] = []
    write(path.name, report)
    component_report["policy_sha256"] = "stale policy"
    write("phase-23-components.json", component_report)
    with pytest.raises(ValueError):
        manage.acceptance()
    result = json.loads((tmp_path / "phase-23-acceptance.json").read_text())
    assert result["blocking"] == [
        "embedded component verification differs from current artifacts/policy"
    ]
