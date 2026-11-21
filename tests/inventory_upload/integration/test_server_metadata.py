"""Owner metadata is atomic and separate from protected inventory identity and software."""

import json
from typing import Any
from uuid import uuid4

import pytest

from tests.inventory_upload.integration.conftest import Browser
from tests.inventory_upload.integration.test_discovery import document, upload, uploader

pytestmark = pytest.mark.inventory_upload


async def send(browser: Browser, value: dict[str, Any], metadata: dict[str, Any]) -> Any:
    return await browser.client.post(
        "/api/v1/dashboard/inventories/upload",
        data={"server_metadata": json.dumps(metadata)},
        files={"file": ("server.json", json.dumps(value).encode(), "application/json")},
        headers={"x-csrf-token": browser.csrf},
    )


def details() -> dict[str, Any]:
    return dict(
        display_name="Mein Webserver",
        description="Eigene Beschreibung",
        environment="Produktion",
        criticality="high",
        exposure="internal",
    )


async def test_metadata_is_atomic_and_retries_preserve_later_edits(browser: Browser) -> None:
    await uploader(browser)
    value, metadata = document(), details()
    received = await send(browser, value, metadata)
    assert received.status_code == 202, received.text
    receipt = received.json()
    with browser.lab.owner() as s:
        server = s.execute(
            "SELECT display_name,description,environment,criticality,exposure "
            "FROM inventory.servers WHERE id=%s",
            (receipt["server_id"],),
        ).fetchone()
        assert server == metadata
        original = s.execute(
            "SELECT payload_json FROM inventory.submissions WHERE id=%s",
            (receipt["submission_id"],),
        ).fetchone()
        assert original and original["payload_json"] == value
        s.execute(
            "UPDATE inventory.servers SET display_name='Nachbearbeitet',version=version+1 "
            "WHERE id=%s",
            (receipt["server_id"],),
        )
    replay = await send(browser, value, metadata)
    assert replay.status_code == 202 and replay.json()["duplicate"]
    conflict = await send(browser, value, {**metadata, "display_name": "Widerspruch"})
    assert conflict.status_code == 409, conflict.text
    value["inventory_id"] = str(uuid4())
    value["host"]["hostname"] = "new-technical-hostname"
    following = await upload(browser, value)
    assert following.status_code == 202, following.text
    assert following.json()["server_id"] == receipt["server_id"]
    with browser.lab.owner() as s:
        server = s.execute(
            "SELECT display_name,environment,criticality FROM inventory.servers WHERE id=%s",
            (receipt["server_id"],),
        ).fetchone()
        assert server == {
            "display_name": "Nachbearbeitet",
            "environment": "Produktion",
            "criticality": "high",
        }


async def test_invalid_or_foreign_metadata_leaves_no_partial_acceptance(browser: Browser) -> None:
    await uploader(browser)
    invalid = document()
    rejected = await send(browser, invalid, {**details(), "monitoring_id": str(uuid4())})
    assert rejected.status_code == 422, rejected.text
    with browser.lab.owner() as s:
        assert not s.execute(
            "SELECT 1 FROM inventory.host_identities WHERE monitoring_id=%s",
            (invalid["host"]["monitoring_id"],),
        ).fetchone()
    value = document()
    received = await send(browser, value, details())
    assert received.status_code == 202, received.text
    other = await uploader(browser)
    with browser.lab.owner() as s:
        s.execute(
            "INSERT INTO security.user_server_access(user_id,server_id,can_read,can_upload) "
            "VALUES(%s,%s,true,true)",
            (other.id, received.json()["server_id"]),
        )
    value["inventory_id"] = str(uuid4())
    denied = await send(browser, value, {**details(), "display_name": "Fremde Änderung"})
    assert denied.status_code == 403, denied.text
    with browser.lab.owner() as s:
        assert not s.execute(
            "SELECT 1 FROM inventory.submissions WHERE inventory_id=%s", (value["inventory_id"],)
        ).fetchone()
        server = s.execute(
            "SELECT display_name FROM inventory.servers WHERE id=%s",
            (received.json()["server_id"],),
        ).fetchone()
        assert server and server["display_name"] == details()["display_name"]
