"Account isolation, shared-server organization, conflicts and group removal on real PostgreSQL."

from typing import Any
from uuid import uuid4

import pytest
from httpx import Response

from tests.authorization.integration.conftest import Actor, actor, call
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.dashboard_administration


async def test_personal_groups_are_private_and_many_to_many(browser: Browser) -> None:
    alice = await actor(browser, ("user",))
    bob = await actor(browser, ("user",))
    admin = await actor(browser)
    sid, hidden = uuid4(), uuid4()
    with browser.lab.owner() as db:
        for server in (sid, hidden):
            db.execute(
                "INSERT INTO inventory.servers(id,display_name,created_by) VALUES(%s,%s,%s)",
                (server, "Personal grouping test", alice.id),
            )
        for user in (alice, bob):
            db.execute(
                (
                    "INSERT INTO "
                    "security.user_server_access(user_id,server_id,can_read,findings_read) "
                    "VALUES(%s,%s,true,true)"
                ),
                (user.id, sid),
            )

    async def request(
        user: Actor, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Response:
        response = await call(browser, user, method, path, body, reauth=False)
        assert isinstance(response, Response)
        return response

    initial = await request(alice, "GET", "groups")
    assert initial.status_code == 200, initial.text
    assert initial.json() == {"items": [], "version": 0}
    first = await request(alice, "POST", "groups", {"name": "Production", "version": 0})
    assert first.status_code == 201, first.text
    data = first.json()
    gid = data["items"][0]["id"]
    second = await request(alice, "POST", "groups", {"name": "Web", "version": data["version"]})
    assert second.status_code == 201, second.text
    data = second.json()
    gids = [g["id"] for g in data["items"]]
    other = await request(bob, "POST", "groups", {"name": "Production", "version": 0})
    assert other.status_code == 201, other.text
    bob_data = other.json()
    assert gid not in [g["id"] for g in bob_data["items"]]
    assert (await request(admin, "GET", "groups")).json()["items"] == []
    denied = await request(
        bob, "PUT", "groups/" + gid, {"name": "Stolen", "version": bob_data["version"]}
    )
    assert denied.status_code == 404, denied.text
    assigned = await request(
        alice, "PUT", f"servers/{sid}/groups", {"group_ids": gids, "version": data["version"]}
    )
    assert assigned.status_code == 200, assigned.text
    data = assigned.json()
    assert all(g["server_ids"] == [str(sid)] for g in data["items"])
    stale = await request(
        alice, "PUT", f"servers/{sid}/groups", {"group_ids": [], "version": data["version"] - 1}
    )
    assert stale.status_code == 409
    foreign = await request(
        bob, "PUT", f"servers/{sid}/groups", {"group_ids": [gid], "version": bob_data["version"]}
    )
    assert foreign.status_code == 404
    inaccessible = await request(
        alice, "PUT", f"servers/{hidden}/groups", {"group_ids": gids, "version": data["version"]}
    )
    assert inaccessible.status_code == 404
    bob_gid = bob_data["items"][0]["id"]
    own = await request(
        bob,
        "PUT",
        f"servers/{sid}/groups",
        {"group_ids": [bob_gid], "version": bob_data["version"]},
    )
    assert own.status_code == 200, own.text
    for user, expected in ((alice, set(gids)), (bob, {bob_gid}), (admin, set())):
        summary = await request(user, "GET", f"security/servers/{sid}")
        assert summary.status_code == 200, summary.text
        assert {g["id"] for g in summary.json()["groups"]} == expected
    assert (await request(bob, "GET", f"security/servers?group_id={gid}")).status_code == 404
    filtered = await request(alice, "GET", f"security/servers?group_id={gid}")
    assert filtered.status_code == 200, filtered.text
    assert filtered.json()["total"] == 1
    deleted = await request(alice, "DELETE", "groups/" + gid, {"version": data["version"]})
    assert deleted.status_code == 200, deleted.text
    assert len(deleted.json()["items"]) == 1
    with browser.lab.owner() as db:
        assert db.execute("SELECT 1 FROM inventory.servers WHERE id=%s", (sid,)).fetchone()
        assert (
            db.execute(
                "SELECT count(*) n FROM inventory.server_group_memberships WHERE server_id=%s",
                (sid,),
            ).fetchone()["n"]
            == 2
        )
        assert (
            db.execute(
                "SELECT primary_group_id FROM inventory.servers WHERE id=%s", (sid,)
            ).fetchone()["primary_group_id"]
            is None
        )
        audit = db.execute(
            (
                "SELECT actor_user_id FROM security.audit_log WHERE "
                "action='personal_groups.assigned' AND object_id=%s"
            ),
            (str(sid),),
        ).fetchall()
        assert {r["actor_user_id"] for r in audit} == {alice.id, bob.id}
        server_version = db.execute(
            "SELECT version FROM inventory.servers WHERE id=%s", (sid,)
        ).fetchone()["version"]
    erased = await browser.client.delete(
        f"/api/v1/dashboard/servers/{sid}",
        headers={
            "cookie": "__Host-cve-session=" + alice.cookie,
            "x-csrf-token": alice.csrf,
            "if-match": f'"{server_version}"',
        },
    )
    assert erased.status_code == 204, erased.text
    with browser.lab.owner() as db:
        assert (
            db.execute(
                "SELECT count(*) n FROM inventory.server_group_memberships WHERE server_id=%s",
                (sid,),
            ).fetchone()["n"]
            == 0
        )
        assert db.execute(
            "SELECT 1 FROM inventory.server_groups WHERE id=%s", (bob_gid,)
        ).fetchone()
    # Retired shared-group mutation APIs are no longer mounted, even for admins.
    assert (await request(admin, "POST", "admin/groups", {"name": "Legacy"})).status_code == 404


async def test_concurrent_group_changes_conflict_without_lost_updates(browser: Browser) -> None:
    import asyncio

    user = await actor(browser, ("user",))
    results = await asyncio.gather(
        *[
            call(browser, user, "POST", "groups", {"name": name, "version": 0}, reauth=False)
            for name in ("Blue", "Green")
        ]
    )
    assert sorted(r.status_code for r in results) == [201, 409]
    state = next(r.json() for r in results if r.status_code == 201)
    group = state["items"][0]
    duplicate = await call(
        browser,
        user,
        "POST",
        "groups",
        {"name": group["name"].lower(), "version": state["version"]},
        reauth=False,
    )
    assert duplicate.status_code == 409
    renamed = await call(
        browser,
        user,
        "PUT",
        "groups/" + group["id"],
        {"name": "Renamed", "description": "Saved description", "version": state["version"]},
        reauth=False,
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["items"][0]["name"] == "Renamed"
    before = await call(browser, user, "GET", "groups")
    missing_csrf = await browser.client.post(
        "/api/v1/dashboard/groups",
        json={"name": "No csrf", "version": before.json()["version"]},
        headers={"cookie": "__Host-cve-session=" + user.cookie},
    )
    assert missing_csrf.status_code == 403
    assert (await call(browser, user, "GET", "groups")).json() == before.json()
