"""Fresh staged release: real mTLS/Ansible, MFA upload and complete controlled notification path."""

from pathlib import Path
from typing import Any

import pytest

from scripts.database import manage as db
from scripts.deployment import orchestration
from scripts.deployment.contracts import Environment, atomic, read
from scripts.infrastructure import mail
from scripts.infrastructure.manage import compose
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.deployment
PROCESSORS = ["cve-inventory", "cve-importer", "cve-enricher", "cve-matcher", "cve-findings"]


async def test_01_real_ansible_submit_duplicate_status_restart_and_revocation(
    browser: Browser, tmp_path: Path
) -> None:
    from tests.inventory_upload.integration.test_ansible_submit import (
        test_real_launcher_uri_submission_duplicate_status_and_restart as submission,
    )

    await submission(browser, tmp_path)


async def test_01b_real_ansible_revoked_token_has_no_receipt(
    browser: Browser,
    tmp_path: Path,
) -> None:
    from tests.inventory_upload.integration.test_ansible_submit import (
        test_actual_revocation_denies_submit_without_receipt as revoke,
    )

    await revoke(browser, tmp_path, "revoke_token")


async def test_02_real_dashboard_mfa_upload_and_acl_revocation(browser: Browser) -> None:
    from tests.inventory_upload.integration.test_concurrency_recovery import (
        test_real_dashboard_mfa_upload_acl_revocation_and_unchanged_groups as upload,
    )

    await upload(browser)


async def test_03_collector_enricher_matching_finding_n8n_postfix_direct_delivery(
    browser: Browser, tmp_path: Path, stage: tuple[Environment, Path, dict[str, Any]]
) -> None:
    from tests.cve_enricher.test_native import Env
    from tests.cve_importer.conftest import Lab as SourceLab
    from tests.findings.test_native import Harness as Findings
    from tests.matching.test_native import Harness as Matching
    from tests.matching.test_native import (
        test_e2e_acceptance_snapshot_enrichment_match_outbox as match,
    )
    from tests.notifications.test_container import (
        test_e2e_finding_n8n_mtls_postfix_direct_and_no_second_submit as deliver,
    )

    target, bundle, manifest = stage
    c = target.config
    original_mail = read(mail.directory(c) / "state/policy.json")
    with db.connect(c) as connection:
        workflow_settings = connection.execute(
            "SELECT enabled FROM automation.workflow_settings WHERE singleton"
        ).fetchone()
        assert workflow_settings is not None
        original_enabled = workflow_settings["enabled"]
        connection.execute("UPDATE automation.workflow_settings SET enabled=false")

    async def finding() -> dict[str, Any]:
        # Avoid competing claims while exercising exactly the application handlers in this
        # staged database. Persistent native worker execution is separately covered by Phase 23.
        from scripts.automation_executor.agent import stop

        stop(c)
        compose(c, ["stop", *PROCESSORS])
        source = Env(SourceLab(c), tmp_path / "source")
        matcher = Matching(browser)
        findings = Findings(browser)
        try:
            await source.importer.run("cve_list")
            await source.drain()
            await match(matcher, tmp_path / "matching")
            await findings.drain()
            with browser.lab.owner() as connection:
                row = connection.execute(
                    "SELECT * FROM findings.current_findings WHERE cve_id='CVE-2026-12345' "
                    "AND latest_matching_status='affected' ORDER BY created_at DESC LIMIT 1"
                ).fetchone()
                assert row is not None
                return dict(row)
        finally:
            await source.importer.transport.close()
            await source.importer.database.close()
            await source.client.close()
            await source.database.close()
            await matcher.database.close()
            await findings.database.close()
            await findings.matcher.database.close()

    try:
        await deliver(c, browser, tmp_path, finding_factory=finding)
        atomic(
            c.root / ".runtime/test-reports/phase-24-business-chain.json",
            {
                "release_id": manifest["release_id"],
                "real_technical_ansible_upload": True,
                "real_dashboard_mfa_upload": True,
                "controlled_import_enrichment_matching": True,
                "actual_finding_event": True,
                "n8n_postfix_direct_test_delivery": True,
                "no_duplicate_submit": True,
                "real_external_notifications": False,
                "processing_mode": (
                    "bounded application handlers against staged PostgreSQL; "
                    "native transport containers"
                ),
            },
        )
    finally:
        with browser.lab.owner() as connection:
            connection.execute(
                "UPDATE automation.workflow_settings SET enabled=%s", (original_enabled,)
            )
            connection.execute(
                "INSERT INTO automation.notification_rules(rule_key,version,config,reason) "
                "SELECT rule_key,version+1,config||'{\"enabled\":false}'::jsonb,"
                "'Phase24 controlled delivery completed' FROM (SELECT DISTINCT ON(rule_key) "
                "* FROM automation.notification_rules ORDER BY rule_key,version DESC) active "
                "WHERE coalesce((config->>'enabled')::boolean,false)"
            )
        atomic(mail.directory(c) / "state/policy.json", original_mail)
        orchestration.start_runtime(target, bundle)


@pytest.fixture(scope="module")
def lifecycle_stage(stage: tuple[Environment, Path, dict[str, Any]]) -> Any:
    target, bundle, manifest = stage
    results: dict[str, bool] = {}
    from scripts.automation_executor.agent import stop

    stop(target.config)
    compose(target.config, ["stop", *PROCESSORS])
    with db.connect(target.config) as connection:
        workflow_settings = connection.execute(
            "SELECT enabled FROM automation.workflow_settings WHERE singleton"
        ).fetchone()
        assert workflow_settings is not None
        original_enabled = workflow_settings["enabled"]
        connection.execute("UPDATE automation.workflow_settings SET enabled=false")
    try:
        yield (*stage, results)
    finally:
        with db.connect(target.config) as connection:
            connection.execute(
                "UPDATE automation.workflow_settings SET enabled=%s", (original_enabled,)
            )
        orchestration.start_runtime(target, bundle)
        if len(results) == 5:
            atomic(
                target.config.root / ".runtime/test-reports/phase-24-business-administration.json",
                {"release_id": manifest["release_id"], **results},
            )


@pytest.mark.parametrize(
    "scenario",
    [
        "triage_csrf_etag",
        "false_positive_reopening",
        "approved_resolution_recurrence",
        "exception_expiry_idempotent",
        "real_browser_administration",
    ],
)
async def test_04_finding_lifecycle_and_real_administrative_browser(
    browser: Browser,
    lifecycle_stage: Any,
    scenario: str,
) -> None:
    from tests.dashboard_administration.test_native import test_real_browser_administration
    from tests.findings import test_api
    from tests.findings.test_native import Harness

    _, _, _, results = lifecycle_stage
    cases = {
        "triage_csrf_etag": test_api.test_triage_etag_actor_csrf_and_mass_assignment,
        "false_positive_reopening": test_api.test_false_positive_close_and_reopen_same_identity,
        "approved_resolution_recurrence": (
            test_api.test_legacy_approved_fix_policy_resolution_and_recurrence
        ),
        "exception_expiry_idempotent": test_api.test_exception_expiry_and_idempotent_maintenance,
        "real_browser_administration": test_real_browser_administration,
    }
    harness = Harness(browser)
    config = browser.lab.config
    original_rate = config.values["WEB_RATE"]
    assert config.project.startswith("cve-db-test-phase24-")
    try:
        if scenario == "real_browser_administration":
            # Match the functional browser lab budget; default limits have their own native test.
            config.values["WEB_RATE"] = "1000r/m"
        await cases[scenario](harness)
        results[scenario] = True
    finally:
        try:
            if scenario == "real_browser_administration":
                from scripts.dashboard.manage import activate

                config.values["WEB_RATE"] = original_rate
                activate(config)
        finally:
            await harness.database.close()
            await harness.matcher.database.close()
