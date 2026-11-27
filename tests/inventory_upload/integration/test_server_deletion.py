"""Owners can permanently erase their servers and inventories."""

from uuid import UUID

import pytest

from tests.inventory_upload.integration.conftest import Browser
from tests.inventory_upload.integration.test_discovery import document, upload, uploader

pytestmark = pytest.mark.inventory_upload


async def test_owner_delete_requires_csrf_and_revision_and_permanently_erases(
    browser: Browser,
) -> None:
    await uploader(browser)
    received = await upload(browser, document())
    assert received.status_code == 202
    sid = received.json()["server_id"]
    listing = await browser.client.get("/api/v1/dashboard/security/servers")
    assert listing.status_code == 200, listing.text
    server = next(r for r in listing.json()["items"] if r["id"] == sid)
    assert server["can_delete"]
    endpoint = "/api/v1/dashboard/servers/" + sid
    assert (await browser.client.delete(endpoint)).status_code == 403
    headers = {"x-csrf-token": browser.csrf}
    assert (await browser.client.delete(endpoint, headers=headers)).status_code == 428
    headers["if-match"] = '"999999"'
    assert (await browser.client.delete(endpoint, headers=headers)).status_code == 412
    headers["if-match"] = '"' + str(server["version"]) + '"'
    assert (await browser.client.delete(endpoint, headers=headers)).status_code == 204
    assert (await browser.client.delete(endpoint, headers=headers)).status_code == 404
    assert (
        await browser.client.get("/api/v1/dashboard/security/servers/" + sid)
    ).status_code == 404
    with browser.lab.owner() as s:
        assert (
            s.execute("SELECT status FROM inventory.servers WHERE id=%s", (UUID(sid),)).fetchone()
            is None
        )
        assert (
            s.execute(
                "SELECT 1 FROM inventory.submissions WHERE id=%s",
                (received.json()["submission_id"],),
            ).fetchone()
            is None
        )
    count = await browser.client.get("/api/v1/findings/active-count")
    assert count.status_code == 200 and count.json() == {"count": 0}


async def test_upload_permission_does_not_authorize_deleting_another_owners_server(
    browser: Browser,
) -> None:
    await uploader(browser)
    receipt = (await upload(browser, document())).json()
    other = await uploader(browser)
    with browser.lab.owner() as s:
        s.execute(
            "INSERT INTO security.user_server_access(user_id,server_id,can_read,can_upload) "
            "VALUES(%s,%s,true,true)",
            (other.id, receipt["server_id"]),
        )
    denied = await browser.client.delete(
        "/api/v1/dashboard/servers/" + receipt["server_id"],
        headers={"x-csrf-token": browser.csrf, "if-match": '"1"'},
    )
    assert denied.status_code == 404


async def test_erased_server_cannot_be_restored(browser: Browser) -> None:
    from tests.authorization.integration.conftest import actor
    from tests.inventory_processor.test_processing import drain
    from tests.server_administration.integration.conftest import send

    await uploader(browser)
    receipt = (await upload(browser, document())).json()
    sid = receipt["server_id"]
    await drain(browser)
    result = await browser.client.delete(
        "/api/v1/dashboard/servers/" + sid,
        headers={"x-csrf-token": browser.csrf, "if-match": '"1"'},
    )
    assert result.status_code == 204
    admin = await actor(browser)
    restored = await send(
        browser,
        admin,
        "POST",
        f"admin/servers/{sid}/restore",
        {"reason": "Restore monitoring"},
        '"2"',
    )
    assert restored.status_code == 404, restored.text
    with browser.lab.owner() as s:
        assert not s.execute("SELECT 1 FROM inventory.servers WHERE id=%s", (sid,)).fetchone()
        assert not s.execute(
            "SELECT 1 FROM inventory.snapshots WHERE server_id=%s", (sid,)
        ).fetchone()
