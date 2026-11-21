"""HTTP administration with real MFA principals, strict inputs and native security state."""

import secrets
from uuid import UUID

import pytest
from cve_api.users.activation import Handoff

from tests.authentication.integration.conftest import Browser

from .conftest import actor, call, role_id, version

pytestmark = [pytest.mark.authorization, pytest.mark.security]


async def test_user_create_manual_activation_list_update_and_lifecycle(browser: Browser) -> None:
    admin = await actor(browser)
    name = "created-" + secrets.token_hex(5)
    created = await call(
        browser,
        admin,
        "POST",
        "admin/users",
        {"username": name, "email": name + "@example.test", "display_name": "Created user"},
    )
    assert created.status_code == 201, created.text
    uid = UUID(created.json()["id"])
    assert created.json()["status"] == "pending_activation"
    no_shortcut = await call(
        browser, admin, "POST", f"admin/users/{uid}/enable", {"version": 1, "reason": "test"}
    )
    assert no_shortcut.status_code == 409
    token = await Handoff(browser.service).issue(uid)
    browser.client.cookies.clear()
    await browser.prepare()
    password = secrets.token_urlsafe(24)
    activated = await browser.post(
        "activation/redeem", {"activation_token": token, "new_password": password}
    )
    assert activated.status_code == 204, activated.text
    assert (await browser.login(name, password)).status_code == 200
    listing = await call(browser, admin, "GET", "admin/users?search=" + name + "&limit=1")
    assert listing.status_code == 200 and listing.json()["total"] == 1
    assert "password_hash" not in listing.text and "verifier" not in listing.text
    patch = await call(
        browser,
        admin,
        "PATCH",
        f"admin/users/{uid}",
        {
            "version": version(browser, uid),
            "reason": "profile correction",
            "display_name": "Changed",
        },
    )
    assert patch.status_code == 200, patch.text
    stale = await call(
        browser,
        admin,
        "PATCH",
        f"admin/users/{uid}",
        {"version": 1, "reason": "stale", "display_name": "Wrong"},
    )
    assert stale.status_code == 409
    for action, expected in [
        ("disable", "disabled"),
        ("enable", "active"),
        ("lock", "locked"),
        ("enable", "active"),
        ("archive", "archived"),
    ]:
        result = await call(
            browser,
            admin,
            "POST",
            f"admin/users/{uid}/{action}",
            {"version": version(browser, uid), "reason": "test"},
        )
        assert result.status_code == 200, result.text
        assert result.json()["status"] == expected
    assert (
        await call(
            browser,
            admin,
            "POST",
            f"admin/users/{uid}/enable",
            {"version": version(browser, uid), "reason": "forbidden restore"},
        )
    ).status_code == 409


@pytest.mark.parametrize("role", ["viewer", "security_analyst"])
async def test_no_management_for_nonadministrators(browser: Browser, role: str) -> None:
    person = await actor(browser, (role,))
    for method, path, body in [
        ("GET", "admin/users", None),
        ("GET", "admin/roles", None),
        (
            "POST",
            "admin/users",
            {"username": "bad", "email": "bad@example.test", "display_name": "bad"},
        ),
    ]:
        response = await call(browser, person, method, path, body)
        assert response.status_code == 403, response.text


async def test_user_admin_restricted_targets_and_standard_role_grants(browser: Browser) -> None:
    admin = await actor(browser)
    manager = await actor(browser, ("user_admin",))
    viewer = await actor(browser, ("viewer",))
    visible = await call(browser, manager, "GET", "admin/users")
    assert visible.status_code == 200
    assert not any(
        "admin" in user["roles"] or "user_admin" in user["roles"]
        for user in visible.json()["items"]
    )
    assert (await call(browser, manager, "GET", f"admin/users/{admin.id}")).status_code == 404
    assert (
        await call(
            browser,
            manager,
            "POST",
            f"admin/users/{admin.id}/disable",
            {"version": version(browser, admin.id), "reason": "forged"},
        )
    ).status_code == 404
    body = {
        "version": version(browser, viewer.id),
        "reason": "standard role",
        "role_ids": [role_id(browser, "security_analyst")],
    }
    response = await call(browser, manager, "PUT", f"admin/users/{viewer.id}/roles", body)
    assert response.status_code == 200, response.text
    escalation = await call(
        browser,
        manager,
        "PUT",
        f"admin/users/{viewer.id}/roles",
        {
            "version": version(browser, viewer.id),
            "reason": "forged admin",
            "role_ids": [role_id(browser, "admin")],
        },
    )
    assert escalation.status_code == 403
    self_raise = await call(
        browser,
        manager,
        "PUT",
        f"admin/users/{manager.id}/roles",
        {
            "version": version(browser, manager.id),
            "reason": "self admin",
            "role_ids": [role_id(browser, "admin")],
        },
    )
    assert self_raise.status_code in (403, 404)


async def test_custom_roles_permissions_revision_and_system_protection(browser: Browser) -> None:
    admin = await actor(browser)
    role = await call(
        browser,
        admin,
        "POST",
        "admin/roles",
        {
            "code": "role_" + secrets.token_hex(4),
            "name": "Role " + secrets.token_hex(4),
            "permissions": ["server:read"],
        },
    )
    assert role.status_code == 201, role.text
    uid = role.json()["id"]
    updated = await call(
        browser,
        admin,
        "PATCH",
        f"admin/roles/{uid}",
        {
            "version": 1,
            "reason": "more read",
            "name": "New " + secrets.token_hex(4),
            "permissions": ["server:read", "inventory:read"],
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["version"] == 2
    assert (
        await call(
            browser,
            admin,
            "PATCH",
            f"admin/roles/{uid}",
            {"version": 1, "reason": "stale", "name": "X", "permissions": []},
        )
    ).status_code == 409
    assert (
        await call(
            browser,
            admin,
            "POST",
            "admin/roles",
            {"code": "evil_role", "name": "Bad", "permissions": ["group:assign"]},
        )
    ).status_code == 422
    system = role_id(browser, "viewer")
    assert (
        await call(
            browser, admin, "DELETE", f"admin/roles/{system}", {"version": 1, "reason": "forged"}
        )
    ).status_code in (403, 404)
    assert (
        await call(
            browser, admin, "DELETE", f"admin/roles/{uid}", {"version": 2, "reason": "remove"}
        )
    ).status_code == 204


@pytest.mark.parametrize(
    "field", ["roles", "is_admin", "status", "mfa_secret", "password_hash", "primary_group_id"]
)
async def test_http_patch_rejects_mass_assignment(browser: Browser, field: str) -> None:
    admin = await actor(browser)
    viewer = await actor(browser, ("viewer",))
    response = await call(
        browser,
        admin,
        "PATCH",
        f"admin/users/{viewer.id}",
        {
            "version": version(browser, viewer.id),
            "reason": "forged",
            "display_name": "New",
            field: "forged",
        },
    )
    assert response.status_code == 422


async def test_csrf_reauth_and_old_sessions_cannot_be_reused(browser: Browser) -> None:
    admin = await actor(browser)
    viewer = await actor(browser, ("viewer",))
    result = await call(
        browser,
        admin,
        "POST",
        f"admin/users/{viewer.id}/disable",
        {"version": version(browser, viewer.id), "reason": "no reauth"},
        reauth=False,
    )
    assert result.status_code == 403
    result = await call(
        browser,
        admin,
        "POST",
        f"admin/users/{viewer.id}/disable",
        {"version": version(browser, viewer.id), "reason": "revoke"},
    )
    assert result.status_code == 200, result.text
    result = await call(browser, viewer, "GET", "me/permissions")
    assert result.status_code == 401
