"""Actual matching → findings, immutable evidence, optimistic commands and stable episodes."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from cve_common.database.engine import Database
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.repository import JobRepository
from cve_findings.contracts import Request
from cve_findings.service import Service

from scripts.database import manage as db
from tests.inventory_upload.integration.conftest import Browser
from tests.matching.test_native import Harness as Matcher

pytestmark = pytest.mark.findings


class Harness:
    def __init__(self, browser: Browser) -> None:
        self.browser = browser
        self.created = 0
        self.matcher = Matcher(browser)
        self.database = Database(
            browser.lab.database("findings_writer").model_copy(
                update={"statement_timeout_ms": 30000}
            )
        )
        self.database.open()
        self.service = Service(self.database)
        self.repository = JobRepository(self.database, self.service.registry())

    async def execute(self) -> Any:
        job = await self.repository.claim(uuid4(), 30)
        if job is None:
            return None
        ctx = ExecutionContext(
            self.repository, job, self.repository.registry.get(job.job_type, 1), asyncio.Event()
        )
        return await self.service.handle(ctx, Request.model_validate(job.payload))

    async def drain(self) -> None:
        for _ in range(2000):
            if await self.execute() is None:
                from tests.application.settle import pending

                if not pending(self.browser, self.repository.registry.names):
                    return
                await asyncio.sleep(0.05)
        raise AssertionError("Unexpected unbounded findings queue")

    def enqueue(self, kind: str, **values: Any) -> str:
        from scripts.cve_findings.manage import enqueue

        return enqueue(self.browser.lab.config, kind, Request.model_validate(values))

    async def create(self, age_hours: int = 0) -> dict[str, Any]:
        if self.created == 0 and not age_hours:
            snapshot = await self.matcher.snapshot()
        else:
            from tests.inventory_processor.test_normalization import sample
            from tests.inventory_processor.test_processing import drain
            from tests.inventory_upload.integration.conftest import provision, technical

            certificate = "client" if self.created == 0 else "client-new"
            upload = await provision(self.browser, certificate=certificate)
            value = sample()
            if age_hours:
                value["captured_at"] = (datetime.now(UTC) - timedelta(hours=age_hours)).isoformat()
            value["server_id"] = upload.server["id"]
            value["packages"]["items"][0]["source_package"] = {
                "name": "apache2",
                "version": value["packages"]["items"][0]["version"],
            }
            response = await technical(
                self.browser, upload, json.dumps(value).encode(), certificate=certificate
            )
            assert response.status_code == 202, response.text
            await drain(self.browser)
            with self.browser.lab.owner() as c:
                snapshot = c.execute(
                    "SELECT snapshot_id FROM inventory.processing_status WHERE submission_id=%s",
                    (response.json()["submission_id"],),
                ).fetchone()["snapshot_id"]
        self.created += 1
        identity, revision = self.matcher.seed()
        await self.matcher.drain()
        self.matcher.enqueue("evaluate_vulnerability", enrichment_revision_id=revision)
        await self.matcher.drain()
        await self.drain()
        with self.browser.lab.owner() as c:
            row = c.execute(
                (
                    "SELECT * FROM findings.current_findings WHERE cve_id=%s AND latest_mat"
                    "ching_result_id IN (SELECT id FROM matching.result_revisions WHERE sna"
                    "pshot_id=%s)"
                ),
                (identity, snapshot),
            ).fetchone()
            assert row
            return dict(row)

    def get(self, identity: UUID) -> dict[str, Any]:
        with self.browser.lab.owner() as c:
            return dict(
                c.execute(
                    "SELECT * FROM findings.current_findings WHERE id=%s", (identity,)
                ).fetchone()
            )

    def publish(
        self,
        finding: dict[str, Any],
        status: str,
        *,
        coverage: bool = False,
        technical_change: bool = True,
    ) -> UUID:
        result = uuid4()
        with self.browser.lab.owner() as c:
            old = c.execute(
                "SELECT * FROM matching.result_revisions WHERE id=%s",
                (finding["latest_matching_result_id"],),
            ).fetchone()
            value = old["result"]
            value["status"] = status
            for comp in value["components"]:
                comp["status"] = status
                comp["conflicts"] = []
                if status == "affected" and technical_change:
                    comp["reason"] = "new_technical_evidence"
            if coverage:
                value["data_quality"] = "complete"
                value["coverage"].update(
                    global_negative=True, sections={"packages": "complete", "os": "complete"}
                )
            c.execute(
                (
                    "INSERT INTO matching.result_revisions(id,run_id,server_id,snapshot_id,"
                    "identity,enrichment_revision_id,rule_version,fingerprint,status,reason"
                    ",result) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'fixture_proof',%s::jsonb)"
                ),
                (
                    result,
                    old["run_id"],
                    old["server_id"],
                    old["snapshot_id"],
                    old["identity"],
                    old["enrichment_revision_id"],
                    old["rule_version"],
                    hashlib.sha256(str(result).encode()).digest(),
                    status,
                    json.dumps(value),
                ),
            )
        with db.connect(self.browser.lab.config, "matcher") as c:
            c.execute("SELECT matching.publish(%s,%s)", (result, uuid4()))
        return result


@pytest.fixture
async def harness(browser: Browser, tmp_path: Any) -> Any:
    # Seed actual source revisions even when this module is selected on its own.
    from tests.cve_enricher.test_native import Env
    from tests.cve_importer.conftest import Lab

    with browser.lab.owner() as c:
        present = c.execute("SELECT 1 FROM cve.source_revisions LIMIT 1").fetchone()
    if not present:
        source = Env(Lab(browser.lab.config), tmp_path / "sources")
        try:
            await source.importer.run("cve_list")
            await source.drain()
        finally:
            await source.importer.transport.close()
            await source.importer.database.close()
            await source.client.close()
            await source.database.close()
    value = Harness(browser)
    try:
        await value.drain()
        yield value
    finally:
        await value.database.close()
        await value.matcher.database.close()


async def test_e2e_matching_to_stable_finding_and_receipts(harness: Harness) -> None:
    f = await harness.create()
    assert f["status"] == "open" and f["latest_matching_status"] == "affected"
    assert f["technical_is_current"] and f["current_priority"] == "unrated"
    with harness.browser.lab.owner() as c:
        observations = c.execute(
            "SELECT * FROM findings.match_observations WHERE finding_id=%s", (f["id"],)
        ).fetchall()
        assert len(observations) == 1
        events = c.execute(
            "SELECT * FROM automation.event_outbox WHERE payload->>'finding_id'=%s", (str(f["id"]),)
        ).fetchall()
        assert {v["event_type"] for v in events} >= {
            "finding.created",
            "finding.confirmed_affected",
        }
        input_event = c.execute(
            (
                "SELECT id FROM automation.event_outbox WHERE event_type='matching.created'"
                " AND payload->>'result_id'=%s"
            ),
            (str(f["latest_matching_result_id"]),),
        ).fetchone()["id"]
    harness.enqueue("consume_matching_event", event_id=input_event)
    await harness.drain()
    assert harness.get(f["id"])["version"] == f["version"]


@pytest.mark.parametrize(
    "status", ["unknown", "potentially_affected", "not_applicable", "not_affected"]
)
async def test_uncertain_evidence_never_resolves(harness: Harness, status: str) -> None:
    f = await harness.create()
    harness.publish(f, status)
    await harness.drain()
    newer = harness.get(f["id"])
    assert newer["status"] == "open" and newer["latest_matching_status"] == status
    assert newer["first_seen_at"] == f["first_seen_at"]
    assert newer["resolved_at"] is None


@pytest.mark.parametrize("workers", [2, 4])
async def test_concurrent_reconciliation_deduplicates(harness: Harness, workers: int) -> None:
    f = await harness.create()
    for _ in range(workers):
        harness.enqueue(
            "reevaluate",
            result_id=f["latest_matching_result_id"],
            current_version=f["matching_version"],
        )
    await asyncio.gather(*(harness.execute() for _ in range(workers)))
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM findings.findings WHERE server_id=%s AND cve_id"
                    "=%s AND model_version=2"
                ),
                (f["server_id"], f["cve_id"]),
            ).fetchone()["n"]
            == 1
        )
        assert (
            c.execute(
                "SELECT count(*) n FROM findings.episodes WHERE finding_id=%s", (f["id"],)
            ).fetchone()["n"]
            == 1
        )
    assert harness.get(f["id"])["version"] == f["version"]


async def test_historical_publication_cannot_overwrite_current(harness: Harness) -> None:
    f = await harness.create()
    new = harness.publish(f, "unknown")
    await harness.drain()
    current = harness.get(f["id"])
    harness.enqueue(
        "reevaluate",
        result_id=f["latest_matching_result_id"],
        current_version=f["matching_version"],
    )
    await harness.drain()
    assert harness.get(f["id"])["latest_matching_result_id"] == new
    assert harness.get(f["id"])["version"] == current["version"]


@pytest.mark.parametrize(
    "table",
    [
        "inventory.servers",
        "inventory.server_groups",
        "inventory.snapshots",
        "inventory.packages",
        "cve.source_records",
        "cve.enrichment_revisions",
        "matching.result_revisions",
        "security.users",
        "security.user_server_access",
        "security.api_tokens",
    ],
)
async def test_native_forbidden_writes(harness: Harness, table: str) -> None:
    with (
        pytest.raises(psycopg.errors.InsufficientPrivilege),
        db.connect(harness.browser.lab.config, "findings_writer") as c,
    ):
        c.execute("DELETE FROM " + table + " WHERE false")


@pytest.mark.parametrize(
    "table",
    [
        "episodes",
        "episode_closures",
        "audit_events",
        "notes",
        "assignments",
        "reviews",
        "exceptions",
        "exception_decisions",
        "priority_history",
        "deadlines",
    ],
)
async def test_history_append_only(harness: Harness, table: str) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege), harness.browser.lab.owner() as c:
        # A statement on an empty table does not fire a row trigger; populate the first audit.
        f = await harness.create() if table == "audit_events" else None
        if f:
            c.execute(
                "UPDATE findings.audit_events SET reason='changed' WHERE finding_id=%s", (f["id"],)
            )
        else:
            with db.connect(harness.browser.lab.config, "findings_writer") as role:
                role.execute("DELETE FROM findings." + table + " WHERE false")


async def test_lost_lease_rolls_back_finding_change(harness: Harness) -> None:
    from cve_common.jobs.errors import LeaseLost

    f = await harness.create()
    harness.publish(f, "unknown")
    job = await harness.repository.claim(uuid4(), 0.2)
    assert job
    ctx = ExecutionContext(
        harness.repository, job, harness.repository.registry.get(job.job_type, 1), asyncio.Event()
    )
    await asyncio.sleep(0.3)
    with pytest.raises(LeaseLost):
        await harness.service.handle(ctx, Request.model_validate(job.payload))
    assert harness.get(f["id"])["latest_matching_status"] == "affected"
    assert harness.get(f["id"])["version"] == f["version"]
    await harness.repository.recover()


async def test_unknown_without_prior_candidate_creates_no_finding(harness: Harness) -> None:
    snapshot = await harness.matcher.snapshot()
    identity, revision = harness.matcher.seed()
    await harness.matcher.drain()
    harness.matcher.enqueue(
        "evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=revision
    )
    await harness.matcher.drain()
    with harness.browser.lab.owner() as c:
        old = c.execute(
            ("SELECT id FROM matching.current_evaluations WHERE identity=%s AND snapshot_id=%s"),
            (identity, snapshot),
        ).fetchone()["id"]
    harness.publish({"latest_matching_result_id": old}, "unknown")
    await harness.drain()
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM findings.findings WHERE cve_id=%s AND server_id=(SELECT"
                    " server_id FROM inventory.snapshots WHERE id=%s) AND model_version=2"
                ),
                (identity, snapshot),
            ).fetchone()["n"]
            == 0
        )


async def test_audit_required_at_finding_commit(harness: Harness) -> None:
    f = await harness.create()
    with (
        pytest.raises(psycopg.errors.CheckViolation),
        db.connect(harness.browser.lab.config, "findings_writer") as c,
    ):
        c.execute("UPDATE findings.findings SET version=version+1 WHERE id=%s", (f["id"],))
    assert harness.get(f["id"])["version"] == f["version"]


async def test_risk_refresh_changes_priority_without_new_episode(harness: Harness) -> None:
    f = await harness.create()
    with harness.browser.lab.owner() as c:
        old = c.execute(
            (
                "SELECT * FROM cve.enrichment_revisions WHERE identity=%s ORDER BY created_at D"
                "ESC LIMIT 1"
            ),
            (f["cve_id"],),
        ).fetchone()
        value = old["result"]
        value["cvss"] = [
            {
                "is_preferred": True,
                "validation_status": "valid",
                "calculated_severity": "CRITICAL",
                "cvss_version": "4.0",
                "base_score": 9.9,
                "vector_string": "fixture-reviewed-by-enricher",
            }
        ]
        revision = uuid4()
        c.execute(
            (
                "INSERT INTO cve.enrichment_revisions SELECT %s,identity,rule_version,%s,%s::js"
                "onb,created_at,job_id FROM cve.enrichment_revisions WHERE id=%s"
            ),
            (
                revision,
                hashlib.sha256(str(revision).encode()).digest(),
                json.dumps(value),
                old["id"],
            ),
        )
        c.execute(
            (
                "UPDATE cve.enrichment_identities SET current_revision_id=%s,current_version=cu"
                "rrent_version+1 WHERE identity=%s"
            ),
            (revision, f["cve_id"]),
        )
    harness.enqueue("refresh_priority", identity=f["cve_id"])
    await harness.drain()
    updated = harness.get(f["id"])
    assert updated["current_priority"] == "critical"
    assert (
        updated["current_episode_id"] == f["current_episode_id"]
        and updated["status"] == f["status"]
    )
    assert updated["latest_matching_result_id"] == f["latest_matching_result_id"]
    version = updated["version"]
    harness.enqueue("refresh_priority", identity=f["cve_id"])
    await harness.drain()
    assert harness.get(f["id"])["version"] == version


async def test_performance_hundred_new_findings(harness: Harness, record_property: Any) -> None:
    import time

    f = await harness.create()
    with harness.browser.lab.owner() as c:
        snapshot = c.execute(
            "SELECT snapshot_id FROM matching.result_revisions WHERE id=%s",
            (f["latest_matching_result_id"],),
        ).fetchone()["snapshot_id"]
    for _ in range(100):
        identity, revision = harness.matcher.seed()
        harness.matcher.enqueue(
            "evaluate_candidate_batch", snapshot_id=snapshot, enrichment_revision_id=revision
        )
    await harness.matcher.drain()
    start = time.monotonic()
    await harness.drain()
    elapsed = time.monotonic() - start
    record_property("hundred_findings_seconds", elapsed)
    assert elapsed < 60
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                ("SELECT count(*) n FROM findings.findings WHERE server_id=%s AND model_version=2"),
                (f["server_id"],),
            ).fetchone()["n"]
            >= 101
        )
