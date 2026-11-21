"Actual HTTP registration, optimistic mutation, explicit memberships and lifecycle."

from typing import Any
from uuid import uuid4

import pytest

from tests.authentication.integration.conftest import Browser

from .conftest import actor, create_server, send

pytestmark = [pytest.mark.server_administration, pytest.mark.security]


def tag(obj: dict[str, Any]) -> str:
    return '"' + str(obj["version"]) + '"'


async def test_registration_idempotence_and_patch_preconditions(browser: Browser) -> None:
    admin = await actor(browser)
    request = {"display_name": "registration", "request_id": str(uuid4())}
    one = await send(browser, admin, "POST", "admin/servers", request)
    two = await send(browser, admin, "POST", "admin/servers", request)
    assert one.status_code == two.status_code == 201
    s = one.json()
    assert s["id"] == two.json()["id"] and s["primary_group_id"] is None
    conflict = await send(
        browser, admin, "POST", "admin/servers", {**request, "display_name": "changed"}
    )
    assert conflict.status_code == 409
    path = "admin/servers/" + s["id"]
    for match, expected in [(None, 428), ("1", 400), ('"999"', 412), (one.headers["etag"], 200)]:
        r = await send(
            browser,
            admin,
            "PATCH",
            path,
            {"display_name": "renamed", "criticality": "critical", "exposure": "internet_exposed"},
            match,
        )
        assert r.status_code == expected, r.text
        if expected in {412, 428}:
            assert r.json()["code"] == ("CONFLICT" if expected == 412 else "INVALID_INPUT")
    assert r.json()["id"] == s["id"] and r.json()["version"] == s["version"] + 1
    stale = await send(
        browser, admin, "PATCH", path, {"description": "lost update"}, one.headers["etag"]
    )
    assert stale.status_code == 412
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT count(*) AS n FROM inventory.snapshots WHERE server_id=%s", (s["id"],)
            ).fetchone()["n"]
            == 0
        )
        assert c.execute(
            "SELECT inventory_hostname,inventory_name FROM inventory.servers WHERE id=%s",
            (s["id"],),
        ).fetchone() == {"inventory_hostname": None, "inventory_name": None}


@pytest.mark.parametrize(
    "field",
    [
        "server_uuid",
        "primary_group_id",
        "display_order",
        "packages",
        "os",
        "acl",
        "status",
        "inventory_hostname",
    ],
)
async def test_server_mass_assignment(browser: Browser, field: str) -> None:
    admin = await actor(browser)
    s = await create_server(browser, admin)
    bad = await send(
        browser, admin, "PATCH", "admin/servers/" + s["id"], {field: "invalid"}, tag(s)
    )
    assert bad.status_code == 422, bad.text
