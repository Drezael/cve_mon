"Real database CRUD, YAML validation, ownership, CSRF, audit and concurrent edits."

import asyncio
from typing import Any

import pytest

from tests.authorization.integration.conftest import actor, call
from tests.inventory_upload.integration.conftest import Browser
from tests.unit.test_custom_dashboard_yaml import EXAMPLE

pytestmark = pytest.mark.dashboard_administration
BASE = "custom-dashboards"


async def test_custom_dashboards_are_private_and_persistent(browser: Browser) -> None:
    user = await actor(browser, ("user",))
    other = await actor(browser, ("user",))
    admin = await actor(browser)
    manager = await actor(browser, ("user_admin",))
    assert (await call(browser, manager, "GET", BASE)).status_code == 403
    check = await call(browser, user, "POST", BASE + "/validate", {"yaml": EXAMPLE}, reauth=False)
    assert check.status_code == 200 and check.json()["valid"], check.text
    assert (await call(browser, user, "GET", BASE)).json()["items"] == []
    invalid = await call(
        browser,
        user,
        "POST",
        BASE + "/validate",
        {"yaml": EXAMPLE + "title: duplicate"},
        reauth=False,
    )
    assert invalid.status_code == 200 and not invalid.json()["valid"]
    rejected = await call(
        browser, user, "POST", BASE, {"yaml": "!!python/object:os.system {}"}, reauth=False
    )
    assert rejected.status_code == 422
    created = await call(browser, user, "POST", BASE, {"yaml": EXAMPLE}, reauth=False)
    assert created.status_code == 201, created.text
    board = created.json()
    assert board["yaml"] == EXAMPLE and board["version"] == 1
    path = BASE + "/" + board["id"]
    invalid_update = await call(
        browser,
        user,
        "PUT",
        path,
        {"yaml": EXAMPLE + "query: forbidden", "version": 1},
        reauth=False,
    )
    assert invalid_update.status_code == 422
    assert (await call(browser, user, "GET", path)).json()["version"] == 1
    for stranger in (other, admin):
        assert (await call(browser, stranger, "GET", path)).status_code == 404
        assert (await call(browser, stranger, "GET", BASE)).json()["items"] == []
        denied = await call(
            browser, stranger, "PUT", path, {"yaml": EXAMPLE, "version": 1}, reauth=False
        )
        assert denied.status_code == 404
        denied = await call(browser, stranger, "DELETE", path, {"version": 1}, reauth=False)
        assert denied.status_code == 404
    missing_csrf = await browser.client.post(
        "/api/v1/dashboard/" + BASE,
        json={"yaml": EXAMPLE},
        headers={"cookie": "__Host-cve-session=" + user.cookie},
    )
    assert missing_csrf.status_code == 403
    # A second account may use the same title without accessing the first configuration.
    assert (
        await call(browser, other, "POST", BASE, {"yaml": EXAMPLE}, reauth=False)
    ).status_code == 201
    attempts = await asyncio.gather(
        *[
            call(
                browser,
                user,
                "PUT",
                path,
                {"yaml": EXAMPLE.replace("My board", title), "version": 1},
                reauth=False,
            )
            for title in ("Edited A", "Edited B")
        ]
    )
    assert sorted(response.status_code for response in attempts) == [200, 409]
    saved: dict[str, Any] = (await call(browser, user, "GET", path)).json()
    assert saved["version"] == 2 and saved["yaml"].startswith("# Keep this comment")
    stale_delete = await call(browser, user, "DELETE", path, {"version": 1}, reauth=False)
    assert stale_delete.status_code == 409
    assert (await call(browser, user, "GET", path)).status_code == 200
    with browser.lab.owner() as db:
        persisted = db.execute(
            (
                "SELECT owner_id,yaml_source,configuration,version FROM "
                "dashboard.custom_dashboards WHERE id=%s"
            ),
            (board["id"],),
        ).fetchone()
        assert persisted["owner_id"] == user.id and persisted["yaml_source"] == saved["yaml"]
        assert persisted["configuration"]["title"] == saved["title"]
        audit = db.execute(
            (
                "SELECT actor_user_id FROM security.audit_log WHERE "
                "action='custom_dashboard.updated' AND object_id=%s"
            ),
            (board["id"],),
        ).fetchone()
        assert audit["actor_user_id"] == user.id
    deleted = await call(browser, user, "DELETE", path, {"version": 2}, reauth=False)
    assert deleted.status_code == 200, deleted.text
    assert (await call(browser, user, "GET", path)).status_code == 404
    assert (await call(browser, other, "GET", BASE)).json()["items"]


async def test_shared_dashboards_are_read_only_and_copied_into_the_recipient_account(
    browser: Browser,
) -> None:
    owner = await actor(browser, ("user",))
    recipient = await actor(browser, ("user",))
    original = await call(browser, owner, "POST", BASE, {"yaml": EXAMPLE}, reauth=False)
    assert original.status_code == 201, original.text
    identity = original.json()["id"]
    path = BASE + "/" + identity
    shared = await call(
        browser,
        owner,
        "PUT",
        path + "/shares",
        {"version": 1, "usernames": [recipient.name]},
        reauth=False,
    )
    assert shared.status_code == 200, shared.text
    visible = await call(browser, recipient, "GET", path)
    assert visible.status_code == 200 and not visible.json()["can_edit"]
    assert (await call(browser, recipient, "GET", BASE)).json()["items"][0]["id"] == identity
    assert (
        await call(browser, recipient, "PUT", path, {"yaml": EXAMPLE, "version": 2}, reauth=False)
    ).status_code == 404
    assert (
        await call(browser, recipient, "DELETE", path, {"version": 2}, reauth=False)
    ).status_code == 404
    copied = await call(
        browser,
        recipient,
        "POST",
        path + "/copy",
        {"yaml": EXAMPLE, "title": "My independent copy"},
        reauth=False,
    )
    assert copied.status_code == 201, copied.text
    assert copied.json()["id"] != identity and copied.json()["can_edit"]
    assert copied.json()["config"]["title"] == "My independent copy"
    assert (await call(browser, owner, "GET", path)).json()["yaml"] == EXAMPLE
    revoked = await call(
        browser, owner, "PUT", path + "/shares", {"version": 2, "usernames": []}, reauth=False
    )
    assert revoked.status_code == 200
    assert (await call(browser, recipient, "GET", path)).status_code == 404
    assert (
        await call(browser, recipient, "GET", BASE + "/" + copied.json()["id"])
    ).status_code == 200


@pytest.mark.parametrize("unicode", [False, True])
async def test_large_dashboard_yaml_crosses_real_auth_boundary(
    browser: Browser, unicode: bool
) -> None:
    import yaml

    user = await actor(browser, ("user",))
    config = yaml.safe_load(EXAMPLE)
    config["widgets"] = [
        {
            "id": "text" + str(i),
            "type": "text",
            "title": "Text",
            "text": ("Ä" * 2800 + "\n" * 100) if unicode else "a" * 3000,
        }
        for i in range(3)
    ]
    source = yaml.safe_dump(config, allow_unicode=True)
    assert 8192 < len(source.encode()) <= 32768
    result = await call(browser, user, "POST", BASE + "/validate", {"yaml": source}, reauth=False)
    assert result.status_code == 200 and result.json()["valid"], result.text
    result = await call(browser, user, "POST", BASE, {"yaml": source}, reauth=False)
    assert result.status_code == 201, result.text
    path = BASE + "/" + result.json()["id"]
    updated = await call(browser, user, "PUT", path, {"yaml": source, "version": 1}, reauth=False)
    assert updated.status_code == 200, updated.text
    too_large = await call(
        browser, user, "PUT", path, {"yaml": source + "#" * 32769, "version": 2}, reauth=False
    )
    assert too_large.status_code == 422, too_large.text
