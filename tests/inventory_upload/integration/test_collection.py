"""Collector registrations are tenant-bound and requests only originate from n8n ticks."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import uuid4

import pytest

from scripts.database import manage as db
from tests.authorization.integration.conftest import actor, call
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.inventory_upload


async def credential(browser: Browser) -> tuple[str, dict[str, str]]:
    admin = await actor(browser)
    client = await call(
        browser, admin, "POST", "admin/inventory-clients", {"name": "sbom-" + uuid4().hex[:12]}
    )
    assert client.status_code == 201
    cid = client.json()["id"]
    pki = Path(browser.lab.config.values["TLS_CERT_FILE"]).parent
    cert = await call(
        browser,
        admin,
        "POST",
        f"admin/inventory-clients/{cid}/certificates",
        {"certificate_pem": (pki / "client.crt").read_text()},
    )
    assert cert.status_code == 201
    token = await call(
        browser,
        admin,
        "POST",
        f"admin/inventory-clients/{cid}/tokens",
        {
            "owner_user_id": str(admin.id),
            "certificate_id": cert.json()["id"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert token.status_code == 201, token.text
    return cid, {
        "authorization": "Bearer " + token.json()["token"],
        "x-cve-inventory-certificate": quote((pki / "client.crt").read_text(), safe=""),
    }


async def test_n8n_only_scheduling_and_fenced_collector_claim(browser: Browser) -> None:
    _, headers = await credential(browser)
    prefix = "/api/v1/inventories/collection/"
    created = await browser.technical_client.post(
        prefix + "targets",
        headers=headers,
        json={"alias": "application-host", "interval_seconds": 21600},
    )
    assert created.status_code == 200, created.text
    target = created.json()["result"]
    before = await browser.technical_client.post(prefix + "claim", headers=headers, json={})
    assert before.status_code == 200 and before.json()["result"] is None
    from tests.infrastructure.client import request

    wire = request(
        browser.lab.config,
        domain=browser.lab.config.values["INVENTORY_DOMAIN"],
        path=prefix + "claim",
        method="POST",
        client="client",
        body=b"{}",
        headers={"Authorization": headers["authorization"], "Content-Type": "application/json"},
    )
    assert wire.status == 200, wire.body
    with db.connect(browser.lab.config, "workflow_control") as s:
        result = s.execute(
            "SELECT inventory.collection_tick('native-execution','cve-control-inventory') AS n"
        ).fetchone()
        assert result and result["n"] == 1
    claimed = await browser.technical_client.post(prefix + "claim", headers=headers, json={})
    assert claimed.status_code == 200, claimed.text
    job: dict[str, Any] = claimed.json()["result"]
    assert job["alias"] == "application-host" and job["execution_id"] == "native-execution"
    assert (await browser.technical_client.post(prefix + "claim", headers=headers, json={})).json()[
        "result"
    ] is None
    stale = dict(job)
    done = {"request_id": job["request_id"], "lease_token": str(uuid4())}
    assert (
        await browser.technical_client.post(prefix + "finish", headers=headers, json=done)
    ).status_code == 409
    done["lease_token"] = stale["lease_token"]
    assert (
        await browser.technical_client.post(prefix + "finish", headers=headers, json=done)
    ).status_code == 200
    with browser.lab.owner() as s:
        row = s.execute(
            "SELECT state FROM inventory.collection_requests WHERE target_id=%s", (target,)
        ).fetchone()
        assert row and row["state"] == "failed"
    # A new n8n request is completed only with a fresh submission from this collector.
    await browser.technical_client.post(
        prefix + "targets", headers=headers, json={"alias": "application-host", "request_now": True}
    )
    with db.connect(browser.lab.config, "workflow_control") as s:
        s.execute("SELECT inventory.collection_tick('next-execution','cve-control-inventory')")
    current = (
        await browser.technical_client.post(prefix + "claim", headers=headers, json={})
    ).json()["result"]
    import json

    from tests.matching.test_container_inventory import inventory

    wire = request(
        browser.lab.config,
        domain=browser.lab.config.values["INVENTORY_DOMAIN"],
        path="/api/v1/inventories",
        method="POST",
        client="client",
        body=json.dumps(inventory()).encode(),
        headers={"Authorization": headers["authorization"], "Content-Type": "application/json"},
    )
    assert wire.status == 202, wire.body
    receipt = json.loads(wire.body)
    done = {
        "request_id": current["request_id"],
        "lease_token": current["lease_token"],
        "submission_id": receipt["submission_id"],
    }
    assert (
        await browser.technical_client.post(prefix + "finish", headers=headers, json=done)
    ).status_code == 200
    dashboard = request(
        browser.lab.config,
        domain=browser.lab.config.values["DASHBOARD_DOMAIN"],
        path="/api/v1/dashboard/security/servers/" + receipt["server_id"] + "/containers",
        method="GET",
        headers={
            "Cookie": "__Host-cve-session=" + str(browser.client.cookies.get("__Host-cve-session"))
        },
    )
    assert dashboard.status == 200, dashboard.body
    deleted = await browser.client.delete(
        "/api/v1/dashboard/servers/" + receipt["server_id"],
        headers={"x-csrf-token": browser.csrf, "if-match": '"1"'},
    )
    assert deleted.status_code == 204, deleted.text
    with browser.lab.owner() as s:
        s.execute(
            "UPDATE inventory.collection_targets SET next_due=clock_timestamp() WHERE id=%s",
            (target,),
        )
    with db.connect(browser.lab.config, "workflow_control") as s:
        row = s.execute(
            "SELECT inventory.collection_tick('after-delete','cve-control-inventory') AS n"
        ).fetchone()
        assert row and row["n"] == 0
