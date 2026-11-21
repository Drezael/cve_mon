"""Owner editing and idempotent full scans stay authorized and pass through n8n."""

from uuid import UUID, uuid4

import pytest
from httpx import Response

from tests.authorization.integration.conftest import Actor, actor, call, fresh
from tests.database.helpers import processed, snapshot
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.dashboard_administration


async def test_owner_edit_and_manual_full_scan(browser: Browser) -> None:
    owner = await actor(browser, ("user",))
    reader = await actor(browser, ("user",))
    sid, empty = uuid4(), uuid4()
    with browser.lab.owner() as db:
        db.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
        for server in (sid, empty):
            db.execute(
                "INSERT INTO inventory.servers(id,display_name,created_by) VALUES(%s,%s,%s)",
                (server, "Manual scan test", owner.id),
            )
        for user in (owner, reader):
            for server in (sid, empty):
                db.execute(
                    "INSERT INTO security.user_server_access"
                    "(user_id,server_id,can_read,findings_read) "
                    "VALUES(%s,%s,true,true)",
                    (user.id, server),
                )
        snap = snapshot(db, sid)
        processed(db, snap)
        db.execute(
            "INSERT INTO inventory.server_current_snapshots(server_id,snapshot_id) VALUES(%s,%s)",
            (sid, snap),
        )
    view = await call(browser, owner, "GET", f"security/servers/{sid}")
    assert view.status_code == 200, view.text
    assert view.json()["can_edit"] and view.json()["can_scan"]
    other = await call(browser, reader, "GET", f"security/servers/{sid}")
    assert not other.json()["can_edit"] and not other.json()["can_scan"]
    for person, expected in ((reader, 404), (owner, 200)):
        fresh(browser, person)
        result = await browser.client.patch(
            f"/api/v1/dashboard/admin/servers/{sid}",
            json={"display_name": "Edited by owner"},
            headers={
                "cookie": "__Host-cve-session=" + person.cookie,
                "x-csrf-token": person.csrf,
                "if-match": '"1"',
            },
        )
        assert result.status_code == expected, result.text
    key = str(uuid4())

    async def scan(person: Actor, server: UUID, identity: str) -> Response:
        return await browser.client.post(
            f"/api/v1/dashboard/servers/{server}/scan",
            headers={
                "cookie": "__Host-cve-session=" + person.cookie,
                "x-csrf-token": person.csrf,
                "idempotency-key": identity,
            },
        )

    denied = await scan(reader, sid, str(uuid4()))
    assert denied.status_code == 403, denied.text
    missing = await scan(owner, empty, str(uuid4()))
    assert missing.status_code == 422, missing.text
    first = await scan(owner, sid, key)
    assert first.status_code == 202, first.text
    again = await scan(owner, sid, key)
    assert again.status_code == 202 and again.json() == first.json(), again.text
    assert first.json()["snapshot_id"] == str(snap)
    with browser.lab.owner() as db:
        job = db.execute(
            "SELECT job_type,payload FROM automation.jobs WHERE id=%s", (first.json()["job_id"],)
        ).fetchone()
        assert job["job_type"] == "matching.evaluate_snapshot"
        assert job["payload"]["snapshot_id"] == str(snap)
        assert not job["payload"].get("cve_ids")
        assert db.execute(
            "SELECT 1 FROM automation.n8n_queue WHERE job_id=%s AND kind='task'",
            (first.json()["job_id"],),
        ).fetchone()
