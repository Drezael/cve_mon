"""The dashboard only queues; fenced n8n FIFO decisions start the real import later."""

from collections.abc import Iterator
from typing import Any, cast
from uuid import uuid4

import psycopg
import pytest
from cve_importer.contracts import Configuration

from scripts.cve_importer.manage import directory
from scripts.database import manage as db
from tests.authentication.integration.conftest import Lab
from tests.authorization.integration.conftest import actor
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.inventory_upload


@pytest.fixture(scope="module")
def upload_lab() -> Iterator[Lab]:
    from tests.inventory_upload.integration.conftest import isolated_upload_lab

    yield from isolated_upload_lab()


async def test_refresh_waits_for_n8n_and_has_one_fenced_receipt(browser: Browser) -> None:
    config = browser.lab.config
    path = directory(config) / "sources.json"
    path.write_text(Configuration().model_dump_json())
    browser.client._transport.app.state.cve_configuration_file = path  # type: ignore[attr-defined]
    await actor(browser)
    key = str(uuid4())
    headers = {"x-csrf-token": browser.csrf, "Idempotency-Key": key}
    with browser.lab.owner() as s:
        before = s.execute("SELECT count(*) AS n FROM cve.import_runs").fetchone()["n"]
        s.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
    first = await browser.client.post("/api/v1/dashboard/cve-data/refresh", headers=headers)
    assert first.status_code == 202, first.text
    second = await browser.client.post("/api/v1/dashboard/cve-data/refresh", headers=headers)
    assert second.json() == first.json()
    with browser.lab.owner() as s:
        assert s.execute("SELECT count(*) AS n FROM cve.import_runs").fetchone()["n"] == before
        item = s.execute(
            "SELECT * FROM automation.n8n_queue WHERE id=%s", (first.json()["jobs"][0]["id"],)
        ).fetchone()
        assert item["state"] == "pending" and item["kind"] == "command"
    with browser.lab.owner() as s:
        queued = s.execute(
            "SELECT count(*) n FROM automation.n8n_queue WHERE state='pending'"
        ).fetchone()["n"]
        own = s.execute(
            "SELECT count(*) n FROM automation.n8n_queue WHERE correlation_id=%s "
            "AND kind='command' AND message_type='cve.refresh'",
            (key,),
        ).fetchone()["n"]
        assert own == 1
    status = (await browser.client.get("/api/v1/dashboard/cve-data")).json()
    assert (
        status["queue"]["pending"] >= 1 and status["queue"]["position"] >= 1 and status["updating"]
    )
    for _ in range(queued + 1):
        with db.connect(config, "workflow_control") as s:
            item = cast(
                Any,
                s.execute("SELECT automation.n8n_claim('first','cve-control-queue') v").fetchone(),
            )["v"]
            assert item["kind"] != "empty"
            if item["id"] == first.json()["jobs"][0]["id"]:
                break
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,'first','cve-control-queue')",
                (item["id"], item["lease_token"], item["kind"]),
            )
    else:
        raise AssertionError("Refresh command did not reach the FIFO head")
    with db.connect(config, "workflow_control") as s:
        assert (
            cast(
                Any,
                s.execute("SELECT automation.n8n_claim('second','cve-control-queue') v").fetchone(),
            )["v"]["kind"]
            == "empty"
        )
    with (
        db.connect(config, "api_security") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("SELECT automation.n8n_claim(%s,%s)", ("forbidden", "cve-control-queue"))
    with (
        db.connect(config, "workflow_control") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute(
            "SELECT automation.n8n_decide(%s,%s,%s,%s,%s)",
            (item["id"], uuid4(), "command", "first", "cve-control-queue"),
        )
    for _ in range(2):
        with db.connect(config, "workflow_control") as s:
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,%s,%s)",
                (item["id"], item["lease_token"], "command", "first", "cve-control-queue"),
            )
    with browser.lab.owner() as s:
        assert s.execute("SELECT count(*) AS n FROM cve.import_runs").fetchone()["n"] == before + 1
        job = s.execute(
            "SELECT job_id FROM cve.import_runs ORDER BY created_at DESC LIMIT 1"
        ).fetchone()["job_id"]
        assert (
            s.execute("SELECT status FROM automation.jobs WHERE id=%s", (job,)).fetchone()["status"]
            == "pending"
        )
    # The command has finished, but the importer still waits for its own FIFO task receipt.
    with db.connect(config, "importer") as s:
        assert not s.execute(
            "SELECT * FROM automation.claim_job(ARRAY['cve.import.cve_list'],%s,30)", (uuid4(),)
        ).fetchone()
    previous = item["sequence"]
    for _ in range(20):
        with db.connect(config, "workflow_control") as s:
            row = s.execute("SELECT automation.n8n_claim('next','cve-control-queue') v").fetchone()
            assert row is not None
            item = row["v"]
            assert item["sequence"] > previous
            previous = item["sequence"]
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,%s,%s)",
                (item["id"], item["lease_token"], item["kind"], "next", "cve-control-queue"),
            )
        if item["kind"] == "task":
            break
    else:
        raise AssertionError("Import task never reached FIFO head")
    with browser.lab.owner() as s:
        assert (
            s.execute("SELECT status FROM automation.jobs WHERE id=%s", (job,)).fetchone()["status"]
            == "queued"
        )
        s.execute(
            "UPDATE automation.jobs SET status='cancelled',finished_at=clock_timestamp() "
            "WHERE id=%s",
            (job,),
        )
        assert s.execute(
            "SELECT 1 FROM automation.n8n_queue WHERE kind='result' AND job_id=%s", (job,)
        ).fetchone()
        s.execute("UPDATE automation.workflow_settings SET enabled=false")
    # A later queued request may resume a failed import's committed checkpoint.
    with browser.lab.owner() as s:
        s.execute(
            "UPDATE cve.import_runs SET progress='{}'::jsonb || "
            "jsonb_build_object('checkpoint','fixture') WHERE job_id=%s",
            (job,),
        )
        s.execute("UPDATE automation.workflow_settings SET enabled=true")
    retry = await browser.client.post(
        "/api/v1/dashboard/cve-data/refresh", headers={**headers, "Idempotency-Key": str(uuid4())}
    )
    assert retry.status_code == 202, retry.text
    for _ in range(20):
        with db.connect(config, "workflow_control") as s:
            row = s.execute("SELECT automation.n8n_claim('retry','cve-control-queue') v").fetchone()
            assert row
            item = row["v"]
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,'retry','cve-control-queue')",
                (item["id"], item["lease_token"], item["kind"]),
            )
        if item["kind"] == "command":
            break
    else:
        raise AssertionError("Retry command never reached the queue head")
    with browser.lab.owner() as s:
        assert s.execute("SELECT count(*) AS n FROM cve.import_runs").fetchone()["n"] == before + 1
        assert (
            s.execute(
                "SELECT job_id FROM cve.import_runs ORDER BY created_at DESC LIMIT 1"
            ).fetchone()["job_id"]
            != job
        )
        s.execute("UPDATE automation.workflow_settings SET enabled=false")
