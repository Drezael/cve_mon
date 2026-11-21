"""Native permission, FIFO authorization, durable restart and consumer health receipts."""

from uuid import uuid4

import psycopg
import pytest

from scripts.database import manage as db
from tests.authorization.integration.conftest import actor
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.status_integration


async def test_restart_is_authorized_only_through_n8n_and_records_its_result(
    browser: Browser,
) -> None:
    person = await actor(browser)
    url = "/api/v1/status/services/importer/restart"
    identity = uuid4()
    headers = {
        "cookie": "__Host-cve-session=" + person.cookie,
        "x-csrf-token": person.csrf,
        "Idempotency-Key": str(identity),
    }
    payload = {"reason": "Controlled worker recovery"}
    denied = await browser.client.post(
        url, headers={"cookie": headers["cookie"], "Idempotency-Key": str(identity)}, json=payload
    )
    assert denied.status_code == 403
    with browser.lab.owner() as s:
        s.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
    first = await browser.client.post(url, headers=headers, json=payload)
    assert first.status_code == 202, first.text
    assert first.json()["state"] == "waiting"
    second = await browser.client.post(url, headers=headers, json=payload)
    assert second.json() == first.json()
    with db.connect(browser.lab.config, "dashboard_admin") as s:
        row = s.execute("SELECT status.claim_restart() AS value").fetchone()
        assert row and row["value"] is None
    with (
        db.connect(browser.lab.config, "api_security") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("SELECT status.claim_restart()")
    for _ in range(50):
        with db.connect(browser.lab.config, "workflow_control") as s:
            row = s.execute(
                "SELECT automation.n8n_claim('restart-test','cve-control-queue') AS v"
            ).fetchone()
            assert row
            item = row["v"]
            assert item["kind"] != "empty"
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,%s,%s)",
                (
                    item["id"],
                    item["lease_token"],
                    item["kind"],
                    "restart-test",
                    "cve-control-queue",
                ),
            )
        if item["id"] == first.json()["queue_id"]:
            break
    else:
        raise AssertionError("Restart command did not reach FIFO head")
    with browser.lab.owner() as s:
        row = s.execute(
            "SELECT state,execution_id FROM status.service_restarts WHERE id=%s", (identity,)
        ).fetchone()
        assert row == {"state": "authorized", "execution_id": "restart-test"}
        s.execute(
            "UPDATE automation.n8n_queue SET finished_at=clock_timestamp()-interval '3 seconds' "
            "WHERE id=%s",
            (first.json()["queue_id"],),
        )
    with db.connect(browser.lab.config, "dashboard_admin") as s:
        row = s.execute("SELECT status.claim_restart() AS v").fetchone()
        assert row
        claimed = row["v"]
        assert claimed["service_id"] == "importer"
    with (
        db.connect(browser.lab.config, "dashboard_admin") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("SELECT status.finish_restart(%s,%s,true,NULL,10,11)", (identity, uuid4()))
    with db.connect(browser.lab.config, "dashboard_admin") as s:
        s.execute(
            "SELECT status.finish_restart(%s,%s,true,NULL,10,11)",
            (identity, claimed["lease_token"]),
        )
    with browser.lab.owner() as s:
        assert (
            s.execute(
                "SELECT state FROM status.service_restarts WHERE id=%s", (identity,)
            ).fetchone()["state"]
            == "succeeded"
        )
        result = s.execute(
            "SELECT id,payload FROM automation.n8n_queue WHERE kind='result' "
            "AND message_type='service.restart' AND correlation_id=%s",
            (identity,),
        ).fetchone()
        assert result and result["payload"]["status"] == "succeeded"
    # A restart result must pass the generic result branch, leaving the FIFO unblocked.
    with db.connect(browser.lab.config, "workflow_control") as s:
        row = s.execute(
            "SELECT automation.n8n_claim('result-test','cve-control-queue') v"
        ).fetchone()
        assert row
        item = row["v"]
        assert item["id"] == str(result["id"]) and item["kind"] == "result"
        s.execute(
            "SELECT automation.n8n_decide(%s,%s,'result','result-test','cve-control-queue')",
            (item["id"], item["lease_token"]),
        )
    history = await browser.client.get(
        "/api/v1/status/admin/restarts", headers={"cookie": headers["cookie"]}
    )
    assert history.status_code == 200 and len(history.json()["targets"]) == 9
    assert "lease_token" not in history.text
    analyst = await actor(browser, ("security_analyst",))
    refused = await browser.client.post(
        url,
        headers={
            "cookie": "__Host-cve-session=" + analyst.cookie,
            "x-csrf-token": analyst.csrf,
            "Idempotency-Key": str(uuid4()),
        },
        json=payload,
    )
    assert refused.status_code == 403


async def test_actual_queue_consumer_heartbeat_expires_and_virtual_services_cannot_restart(
    browser: Browser,
) -> None:
    person = await actor(browser)
    with browser.lab.owner() as s:
        s.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
    with db.connect(browser.lab.config, "workflow_control") as s:
        s.execute("SELECT automation.n8n_touch('heartbeat-test','cve-control-queue')")
    headers = {"cookie": "__Host-cve-session=" + person.cookie}
    value = (await browser.client.get("/api/v1/status/overview", headers=headers)).json()
    assert value["control"]["workflow_state"] == "healthy"
    with browser.lab.owner() as s:
        s.execute(
            "UPDATE automation.n8n_consumer SET seen_at=clock_timestamp()-interval '4 minutes'"
        )
    value = (await browser.client.get("/api/v1/status/overview", headers=headers)).json()
    assert value["control"]["workflow_state"] == "unavailable"
    denied = await browser.client.post(
        "/api/v1/status/services/postgres/restart",
        headers=headers | {"x-csrf-token": person.csrf, "Idempotency-Key": str(uuid4())},
        json={"reason": "Not a microservice"},
    )
    assert denied.status_code == 404
