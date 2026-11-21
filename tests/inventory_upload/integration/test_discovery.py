"""Discovery uploads create owned servers atomically and retain immutable original JSON."""

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from tests.authorization.integration.conftest import Actor, actor
from tests.inventory_processor.test_normalization import sample
from tests.inventory_processor.test_processing import drain
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.inventory_upload


def document() -> dict[str, Any]:
    value = sample()
    value.pop("server_id")
    value["schema_version"] = "1.2"
    value["host"] = {"monitoring_id": str(uuid4()), "hostname": "discovered-host"}
    return value


async def uploader(browser: Browser) -> Actor:
    person = await actor(browser, roles=("viewer",))
    with browser.lab.owner() as s:
        role = s.execute(
            "INSERT INTO security.roles(code,name) VALUES(%s,%s) RETURNING id",
            ("uploader_" + uuid4().hex[:12], "Uploader " + uuid4().hex[:12]),
        ).fetchone()
        assert role
        s.execute(
            "INSERT INTO security.role_permissions(role_id,permission_code) "
            "VALUES(%s,'server:inventory:manage')",
            (role["id"],),
        )
        s.execute(
            "INSERT INTO security.user_roles(user_id,role_id) VALUES(%s,%s)",
            (person.id, role["id"]),
        )

    return person


async def upload(browser: Browser, value: dict[str, Any]) -> Any:
    return await browser.client.post(
        "/api/v1/dashboard/inventories/upload",
        files={"file": ("server.json", json.dumps(value).encode(), "application/json")},
        headers={"x-csrf-token": browser.csrf},
    )


async def test_first_upload_creates_server_and_following_upload_reuses_it(browser: Browser) -> None:
    await uploader(browser)
    value = document()
    result = await upload(browser, value)
    assert result.status_code == 202, result.text
    receipt = result.json()
    with browser.lab.owner() as s:
        server = s.execute(
            "SELECT display_name,created_by FROM inventory.servers WHERE id=%s",
            (receipt["server_id"],),
        ).fetchone()
        assert server and server["display_name"] == value["host"]["hostname"]
        grant = s.execute(
            "SELECT can_read,can_upload,findings_read FROM security.user_server_access "
            "WHERE server_id=%s AND user_id=%s",
            (receipt["server_id"], server["created_by"]),
        ).fetchone()
        assert grant and all(grant.values())
        original = s.execute(
            "SELECT payload_json FROM inventory.submissions WHERE id=%s",
            (receipt["submission_id"],),
        ).fetchone()
        assert original and original["payload_json"] == value
    duplicate = await upload(browser, value)
    assert duplicate.status_code == 202 and duplicate.json()["duplicate"] is True
    value["inventory_id"] = str(uuid4())
    value["captured_at"] = datetime.now(UTC).isoformat()
    value["host"]["hostname"] = "renamed-host"
    changed = await upload(browser, value)
    assert changed.status_code == 202 and changed.json()["server_id"] == receipt["server_id"]
    await drain(browser)
    with browser.lab.owner() as s:
        state = s.execute(
            "SELECT status FROM inventory.processing_status WHERE submission_id=%s",
            (changed.json()["submission_id"],),
        ).fetchone()
        assert state and state["status"] == "completed"


async def test_other_uploader_cannot_claim_existing_host(browser: Browser) -> None:
    await uploader(browser)
    value = document()
    assert (await upload(browser, value)).status_code == 202
    await uploader(browser)
    value["inventory_id"] = str(uuid4())
    assert (await upload(browser, value)).status_code == 404


async def test_invalid_or_conflicting_inventory_leaves_no_server(browser: Browser) -> None:
    await uploader(browser)
    value = document()
    first = await upload(browser, value)
    assert first.status_code == 202
    bad = document()
    bad["inventory_id"] = value["inventory_id"]
    assert (await upload(browser, bad)).status_code == 409
    with browser.lab.owner() as s:
        assert not s.execute(
            "SELECT 1 FROM inventory.host_identities WHERE monitoring_id=%s",
            (bad["host"]["monitoring_id"],),
        ).fetchone()
    viewer = await actor(browser, roles=("viewer",))
    assert viewer
    assert (await upload(browser, document())).status_code == 403


async def test_collector_credential_discovers_multiple_servers_and_follows_owner_rights(
    browser: Browser,
) -> None:
    from datetime import timedelta
    from pathlib import Path

    from tests.authorization.integration.conftest import call
    from tests.inventory_upload.integration.conftest import Upload, technical

    owner = await uploader(browser)
    admin = await actor(browser)
    client = await call(
        browser, admin, "POST", "admin/inventory-clients", {"name": "discover-" + uuid4().hex[:12]}
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
            "owner_user_id": str(owner.id),
            "certificate_id": cert.json()["id"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert token.status_code == 201, token.text
    assert token.json()["scope"] == "inventory:discover"
    credentials = Upload(
        admin, {}, cid, cert.json()["id"], token.json()["id"], token.json()["token"]
    )
    receipts = []
    for _ in range(2):
        value = document()
        result = await technical(browser, credentials, json.dumps(value).encode())
        assert result.status_code == 202, result.text
        assert result.json()["monitoring_id"] == value["host"]["monitoring_id"]
        receipts.append(result.json())
    assert receipts[0]["server_id"] != receipts[1]["server_id"]
    from tests.infrastructure.client import request

    wire = request(
        browser.lab.config,
        domain=browser.lab.config.values["INVENTORY_DOMAIN"],
        path="/api/v1/inventories",
        method="POST",
        client="client",
        body=json.dumps(value).encode(),
        headers={
            "Authorization": "Bearer " + credentials.token,
            "Content-Type": "application/json",
        },
    )
    assert wire.status == 202, wire.body
    assert json.loads(wire.body)["monitoring_id"] == value["host"]["monitoring_id"]

    from urllib.parse import quote

    status = await browser.technical_client.get(
        receipts[0]["status_url"],
        headers={
            "authorization": "Bearer " + credentials.token,
            "x-cve-inventory-certificate": quote((pki / "client.crt").read_text(), safe=""),
        },
    )
    assert status.status_code == 200
    assert status.json()["monitoring_id"] == receipts[0]["monitoring_id"]

    with browser.lab.owner() as s:
        s.execute(
            "DELETE FROM security.user_roles ur USING security.role_permissions rp "
            "WHERE ur.role_id=rp.role_id AND ur.user_id=%s "
            "AND rp.permission_code='server:inventory:manage'",
            (owner.id,),
        )
    assert (
        await technical(browser, credentials, json.dumps(document()).encode())
    ).status_code == 401


async def test_parallel_first_uploads_share_one_server(browser: Browser) -> None:
    import asyncio
    import copy

    await uploader(browser)
    first = document()
    second = copy.deepcopy(first)
    second["inventory_id"] = str(uuid4())
    results = await asyncio.gather(upload(browser, first), upload(browser, second))
    assert [r.status_code for r in results] == [202, 202]
    assert results[0].json()["server_id"] == results[1].json()["server_id"]


async def test_machine_collision_is_rejected_and_ssh_rotation_preserves_server(
    browser: Browser,
) -> None:
    import copy
    import hashlib

    await uploader(browser)
    first = document()
    first["host"]["machine_id_hash"] = hashlib.sha256(uuid4().bytes).hexdigest()
    first["host"]["ssh_host_key_fingerprint"] = "SHA256:" + "A" * 43
    result = await upload(browser, first)
    assert result.status_code == 202
    clone = copy.deepcopy(first)
    clone["inventory_id"] = str(uuid4())
    clone["host"]["monitoring_id"] = str(uuid4())
    assert (await upload(browser, clone)).status_code == 409
    first["inventory_id"] = str(uuid4())
    first["host"]["ssh_host_key_fingerprint"] = "SHA256:" + "B" * 43
    rotated = await upload(browser, first)
    assert rotated.status_code == 202 and rotated.json()["server_id"] == result.json()["server_id"]


async def test_legacy_inventory_needs_no_manual_target_selection_or_extra_admin_grant(
    browser: Browser,
) -> None:
    from tests.server_administration.integration.conftest import create_server

    admin = await actor(browser)
    server = await create_server(browser, admin)
    legacy = sample()
    legacy["server_id"] = server["id"]
    result = await upload(browser, legacy)
    assert result.status_code == 202
    assert result.json()["server_id"] == server["id"]
    assert "monitoring_id" not in result.json()
