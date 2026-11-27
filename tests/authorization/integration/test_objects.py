"BOLA, SQL-level pagination/counts and complete separation of upload/group capabilities."

import secrets
from uuid import UUID, uuid4

import pytest
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.administration import Administration
from cve_api.authorization.errors import Denied

from tests.authentication.integration.conftest import Browser

from .conftest import actor, call

pytestmark = [pytest.mark.authorization, pytest.mark.security]


def servers(browser: Browser, count: int = 3) -> list[UUID]:
    with browser.lab.owner() as c:
        result = []
        for _ in range(count):
            name = "object-" + secrets.token_hex(5)
            result.append(
                c.execute(
                    (
                        "INSERT INTO inventory.servers(display_name,inventory_ho"
                        "stname,inventory_name) VALUES(%s,%s,%s) RETURNING id"
                    ),
                    (name, name, name),
                ).fetchone()["id"]
            )
        return sorted(result)


async def test_acl_filter_search_pagination_group_counts_and_no_inheritance(
    browser: Browser,
) -> None:
    admin = await actor(browser)
    viewer = await actor(browser, ("viewer",))
    allowed, hidden, another = servers(browser)
    saved = await call(
        browser,
        admin,
        "PUT",
        f"admin/server-access/{allowed}",
        {
            "version": 0,
            "reason": "view grant",
            "grants": [{"user_id": str(viewer.id), "rights": ["view", "findings_read"]}],
        },
    )
    assert saved.status_code == 200, saved.text
    assert (await call(browser, viewer, "GET", "me/permissions")).status_code == 401
    await browser.login(viewer.name, viewer.password)
    viewer.cookie = browser.client.cookies.get(SESSION_COOKIE) or ""
    viewer.csrf = browser.csrf
    api = Administration(browser.service)
    assert (await api.servers(viewer.cookie, limit=1))["total"] == 1
    rows = await api.servers(viewer.cookie, limit=1)
    assert rows["items"][0]["id"] == allowed
    assert (await api.servers(viewer.cookie, offset=1))["items"] == []
    with browser.lab.owner() as c:
        hidden_name = c.execute(
            "SELECT display_name FROM inventory.servers WHERE id=%s", (hidden,)
        ).fetchone()["display_name"]
        group = c.execute(
            (
                "INSERT INTO inventory.server_groups(name,sort_order,owner_id) "
                "SELECT %s,coalesce(max(sort_order),-1)+1,%s FROM inventory"
                ".server_groups RETURNING id"
            ),
            ("group-" + secrets.token_hex(4), viewer.id),
        ).fetchone()["id"]
        invisible_group = c.execute(
            (
                "INSERT INTO inventory.server_groups(name,sort_order,owner_id) "
                "SELECT %s,coalesce(max(sort_order),-1)+1,%s FROM inventory"
                ".server_groups RETURNING id"
            ),
            ("hidden-" + secrets.token_hex(4), viewer.id),
        ).fetchone()["id"]
        for position, server in enumerate((allowed, hidden)):
            c.execute(
                (
                    "INSERT INTO inventory.server_group_memberships"
                    "(server_id,group_id,display_order) VALUES(%s,%s,%s)"
                ),
                (server, group, position),
            )
        c.execute(
            ("INSERT INTO inventory.server_group_memberships(server_id,group_id) VALUES(%s,%s)"),
            (another, invisible_group),
        )
        # Even a legacy explicit group grant never becomes a browser server capability.
        c.execute(
            ("INSERT INTO security.user_group_access(user_id,group_id) VALUES(%s,%s)"),
            (viewer.id, group),
        )
    assert (await api.servers(viewer.cookie, search=hidden_name))["total"] == 0
    groups = await api.groups(viewer.cookie)
    assert groups == [{"id": group, "name": groups[0]["name"], "visible_servers": 1}]
    with pytest.raises(Denied):
        await api.check_object(viewer.cookie, "server:read", hidden)
    await api.check_object(viewer.cookie, "server:read", allowed)
    with pytest.raises(Denied):
        await api.check_object(viewer.cookie, "inventory:upload:dashboard", allowed)
    with pytest.raises(Denied):
        await api.check_object(viewer.cookie, "group:assign", allowed)


async def test_dashboard_upload_needs_both_role_and_explicit_acl_even_for_admin(
    browser: Browser,
) -> None:
    admin = await actor(browser)
    person = await actor(browser, ("viewer",))
    server = servers(browser, 1)[0]
    api = Administration(browser.service)
    with pytest.raises(Denied):
        await api.check_object(admin.cookie, "inventory:upload:dashboard", server)
    custom = await call(
        browser,
        admin,
        "POST",
        "admin/roles",
        {
            "code": "upload_" + secrets.token_hex(4),
            "name": "Upload " + secrets.token_hex(4),
            "permissions": ["server:read", "inventory:upload:dashboard"],
        },
    )
    assert custom.status_code == 201, custom.text
    with browser.lab.owner() as c:
        c.execute(
            ("INSERT INTO security.user_roles(user_id,role_id) VALUES(%s,%s)"),
            (person.id, custom.json()["id"]),
        )
    with pytest.raises(Denied):
        await api.check_object(person.cookie, "inventory:upload:dashboard", server)
    response = await call(
        browser,
        admin,
        "PUT",
        f"admin/server-access/{server}",
        {
            "version": 0,
            "reason": "upload grant",
            "grants": [{"user_id": str(person.id), "rights": ["view", "inventory_upload"]}],
        },
    )
    assert response.status_code == 200, response.text
    await browser.login(person.name, person.password)
    person.cookie = browser.client.cookies.get(SESSION_COOKIE) or ""
    await api.check_object(person.cookie, "inventory:upload:dashboard", server)
    for protected in ("group:assign", "group:primary:assign", "group:reorder", "server:reorder"):
        with pytest.raises(Denied):
            await api.check_object(person.cookie, protected, server)


async def test_acl_stale_version_unknown_server_and_no_self_grant(browser: Browser) -> None:
    admin = await actor(browser)
    server = servers(browser, 1)[0]
    viewer = await actor(browser, ("viewer",))
    body = {
        "version": 0,
        "reason": "grant",
        "grants": [{"user_id": str(viewer.id), "rights": ["view"]}],
    }
    result = await call(browser, admin, "PUT", f"admin/server-access/{server}", body)
    assert result.status_code == 200
    assert (
        await call(browser, admin, "PUT", f"admin/server-access/{server}", body)
    ).status_code == 409
    assert (
        await call(browser, admin, "PUT", f"admin/server-access/{uuid4()}", body)
    ).status_code == 404
    assert (
        await call(
            browser,
            admin,
            "PUT",
            f"admin/server-access/{server}",
            {
                "version": 1,
                "reason": "self",
                "grants": [{"user_id": str(admin.id), "rights": ["view", "inventory_upload"]}],
            },
        )
    ).status_code == 403
    await browser.login(viewer.name, viewer.password)
    viewer.cookie = browser.client.cookies.get(SESSION_COOKIE) or ""
    viewer.csrf = browser.csrf
    assert (
        await call(browser, viewer, "PUT", f"admin/server-access/{server}", body)
    ).status_code == 403
