"""Real fresh isolated installation of all seven pinned services using the release controller."""

from pathlib import Path
from typing import Any

import pytest

from scripts.deployment import orchestration, preflight, release, state
from scripts.deployment.contracts import Environment, atomic, read

pytestmark = pytest.mark.deployment


def test_fresh_stage_installs_every_pinned_service(
    stage: tuple[Environment, Path, dict[str, Any]],
) -> None:
    target, bundle, manifest = stage
    value = orchestration.smoke(target, bundle)
    assert value["healthy_services"] == 7 and value["all_release_images_running"]
    assert not value["functional_acceptance"]
    assert manifest["production_eligible"] == bool(
        manifest["source"]["git_commit"] and manifest["source"]["clean"]
    )
    assert state.journal(target)[-1]["state"] == "completed"


def test_preflight_and_repeat_are_non_mutating(
    stage: tuple[Environment, Path, dict[str, Any]],
) -> None:
    from scripts.infrastructure.manage import compose

    target, bundle, _ = stage
    before = compose(target.config, ["ps", "-q"]).stdout
    journal = (target.control / "journal.json").read_bytes()
    assert preflight.check(target, bundle)["mode"] == "read_only"
    assert orchestration.rollout(target, bundle)["idempotent"]
    assert before == compose(target.config, ["ps", "-q"]).stdout
    assert (target.control / "journal.json").read_bytes() == journal


def test_release_is_bound_to_current_sources(
    stage: tuple[Environment, Path, dict[str, Any]],
) -> None:
    target, bundle, manifest = stage
    assert release.verify(bundle, current_source=True)["release_id"] == manifest["release_id"]
    assert len(manifest["images"]) == 7
    report = target.config.root / ".runtime/test-reports/phase-24-native-stage.json"
    atomic(
        report,
        {
            "project": target.config.project,
            "release_id": manifest["release_id"],
            "core_pinned_services": True,
            "read_only_preflight": True,
            "idempotent_rollout": True,
            "production_eligible": manifest["production_eligible"],
            "source_sha256": manifest["source"]["sha256"],
            "environment_file": str(target.path),
            "bundle": str(bundle),
        },
    )


def test_full_encrypted_backup_and_isolated_service_recovery(
    stage: tuple[Environment, Path, dict[str, Any]], tmp_path: Path
) -> None:
    import base64
    import os

    from scripts.deployment import recovery

    target, bundle, manifest = stage
    keys = target.config.root / ".runtime/phase24-recovery-keys"
    keys.mkdir(mode=0o700, exist_ok=True)
    key = keys / (target.config.project + ".key")
    key.write_bytes(base64.b64encode(os.urandom(32)))
    key.chmod(0o600)
    from scripts.database import manage as db

    with db.connect(target.config, database="n8n") as connection:
        connection.execute(
            "UPDATE workflow_entity SET active=false,name='Preserved recovered workflow' "
            "WHERE id='cve-control-index'"
        )
    state = (
        target.config.mount_base / "n8n" / target.config.project / "data/cve-bootstrap-state.json"
    )
    state_before = read(state, private=True)
    archive = target.control / "encrypted-backup"
    result = recovery.snapshot(target, bundle, archive, key)
    assert result["source_plaintext_removed"] and result["complete"]
    assert recovery.restore_database_test(target, archive, key)["isolated_restore"]
    recovery.require_verified_backup(target)
    second = orchestration.stage(tmp_path / "recovery")
    try:
        restored = recovery.recover_stage(target, second, bundle, archive, key)
        assert restored["full_service_restore"] and restored["healthy_services"] == 7
        assert restored["database_fingerprints_equal_before_start"]
        second = orchestration.pinned(second, bundle)
        assert recovery.verify_recovered_credentials(second) == 2
        recovered_state = (
            second.config.mount_base
            / "n8n"
            / second.config.project
            / "data/cve-bootstrap-state.json"
        )
        assert read(recovered_state, private=True) == state_before
        with db.connect(second.config, database="n8n") as connection:
            workflow = connection.execute(
                "SELECT active,name FROM workflow_entity WHERE id='cve-control-index'"
            ).fetchone()
            assert workflow and not workflow["active"]
            assert workflow["name"] == "Preserved recovered workflow"
        report = target.config.root / ".runtime/test-reports/phase-24-full-recovery.json"
        atomic(
            report,
            {
                **restored,
                "credentials_decrypted_and_verified": 2,
                "release_id": manifest["release_id"],
                "backup_index_sha256": result["backup_index_sha256"],
            },
        )
    finally:
        orchestration.cleanup_stage(second)


def test_controlled_restart_preserves_data_after_api_and_database_outage(
    stage: tuple[Environment, Path, dict[str, Any]],
) -> None:
    from scripts.database import manage as db
    from scripts.deployment import maintenance
    from scripts.infrastructure.manage import compose

    target, bundle, manifest = stage
    with db.connect(target.config) as connection:
        before = connection.execute("SELECT count(*) n FROM inventory.servers").fetchone()
    compose(target.config, ["stop", "cve-api", "cve-postgres"])
    result = maintenance.restart(target, bundle)
    with db.connect(target.config) as connection:
        after = connection.execute("SELECT count(*) n FROM inventory.servers").fetchone()
    assert before == after
    assert result["healthy_services"] == 7
    atomic(target.control / "outage-exercise.json", {**result, "inventory_preserved": True})
    atomic(
        target.config.root / ".runtime/test-reports/phase-24-outage-exercise.json",
        {**result, "inventory_preserved": True, "release_id": manifest["release_id"]},
    )


def test_offline_image_export_import_preserves_release_identities(
    stage: tuple[Environment, Path, dict[str, Any]],
) -> None:
    from scripts.deployment import artifacts

    target, bundle, manifest = stage
    directory = target.control / "offline-images"
    exported = artifacts.export(bundle, directory)
    artifacts.import_images(bundle, directory)
    assert len(exported["images"]) == 7
    assert orchestration.smoke(target, bundle)["all_release_images_running"]
    atomic(
        target.config.root / ".runtime/test-reports/phase-24-offline-images.json",
        {
            "release_id": manifest["release_id"],
            "exported_and_imported": 7,
            "checksums_verified": True,
            "registry_publication": False,
        },
    )
