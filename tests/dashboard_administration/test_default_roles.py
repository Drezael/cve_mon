"""Standard user accounts, automatic admin membership, and database enforcement."""

from uuid import UUID

import psycopg
import pytest

from tests.authorization.integration.conftest import actor, call, role_id, version
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.dashboard_administration


def codes(browser: Browser, user: UUID) -> set[str]:
    with browser.lab.owner() as s:
        return {
            r["code"]
            for r in s.execute(
                "SELECT r.code FROM security.user_roles a JOIN security.roles r "
                "ON r.id=a.role_id WHERE a.user_id=%s",
                (user,),
            )
        }


async def test_bootstrap_and_administrator_memberships_include_user(browser: Browser) -> None:
    assert codes(browser, browser.lab.bootstrap_id) == {"admin", "user"}
    administrator = await actor(browser)
    target = await actor(browser, ())
    assert codes(browser, administrator.id) == {"admin", "user"}
    response = await call(
        browser,
        administrator,
        "PUT",
        f"admin/users/{target.id}/roles",
        {
            "version": version(browser, target.id),
            "reason": "Promote with inherited base role",
            "role_ids": [role_id(browser, "admin")],
        },
    )
    assert response.status_code == 200, response.text
    assert set(response.json()["role_ids"]) == {role_id(browser, "admin"), role_id(browser, "user")}
    assert codes(browser, target.id) == {"admin", "user"}
    # Replacing all grants with only admin must keep user and must not hit a duplicate insert.
    repeated = await call(
        browser,
        administrator,
        "PUT",
        f"admin/users/{target.id}/roles",
        {
            "version": version(browser, target.id),
            "reason": "Keep admin with implicit user",
            "role_ids": [role_id(browser, "admin")],
        },
    )
    assert repeated.status_code == 200, repeated.text
    assert codes(browser, target.id) == {"admin", "user"}
    # Removing the base role alone is forbidden even outside the HTTP API.
    with (
        pytest.raises(psycopg.errors.CheckViolation, match="also have the user role"),
        browser.lab.owner() as s,
    ):
        s.execute(
            "DELETE FROM security.user_roles WHERE user_id=%s AND role_id="
            "(SELECT id FROM security.roles WHERE code='user')",
            (target.id,),
        )
    assert codes(browser, target.id) == {"admin", "user"}
    demoted = await call(
        browser,
        administrator,
        "PUT",
        f"admin/users/{target.id}/roles",
        {
            "version": version(browser, target.id),
            "reason": "Retain regular account only",
            "role_ids": [role_id(browser, "user")],
        },
    )
    assert demoted.status_code == 200, demoted.text
    assert codes(browser, target.id) == {"user"}


async def test_new_regular_account_receives_user_without_password_or_admin(
    browser: Browser,
) -> None:
    administrator = await actor(browser)
    response = await call(
        browser,
        administrator,
        "POST",
        "admin/users",
        {
            "username": "standard-account",
            "display_name": "Standard account",
            "email": "standard@example.test",
        },
    )
    assert response.status_code == 201, response.text
    uid = UUID(response.json()["id"])
    assert response.json()["status"] == "pending_activation"
    assert codes(browser, uid) == {"user"}
    with browser.lab.owner() as s:
        assert s.execute(
            "SELECT count(*) n FROM security.password_credentials WHERE user_id=%s", (uid,)
        ).fetchone() == {"n": 0}
    manager = await actor(browser, ("user_admin",))
    target = await actor(browser, ())
    granted = await call(
        browser,
        manager,
        "PUT",
        f"admin/users/{target.id}/roles",
        {
            "version": version(browser, target.id),
            "reason": "Assign standard user",
            "role_ids": [role_id(browser, "user")],
        },
    )
    assert granted.status_code == 200, granted.text
    assert codes(browser, target.id) == {"user"}


async def test_user_is_nonadministrative_and_standard_role_is_immutable(browser: Browser) -> None:
    regular = await actor(browser, ("user",))
    permissions = await call(browser, regular, "GET", "me/permissions")
    assert permissions.status_code == 200
    assert "user" in permissions.json()["roles"]
    assert "server:inventory:manage" in permissions.json()["permissions"]
    for forbidden in [
        "user:list",
        "instance:settings:manage",
        "notification:smtp:manage",
        "role:create",
    ]:
        assert forbidden not in permissions.json()["permissions"]
    for path in [
        "admin/users",
        "admin/roles",
        "administration/localization",
        "administration/smtp",
    ]:
        assert (await call(browser, regular, "GET", path)).status_code == 403
    administrator = await actor(browser)
    for account, wanted in [(regular, ["user"]), (administrator, ["admin", "user"])]:
        listing = await call(browser, administrator, "GET", "admin/users?search=" + account.name)
        assert listing.status_code == 200
        listed = next(item for item in listing.json()["items"] if item["id"] == str(account.id))
        assert listed["roles"] == wanted
    roles = await call(browser, administrator, "GET", "admin/roles")
    assert roles.status_code == 200
    user = next(r for r in roles.json() if r["code"] == "user")
    assert user["is_system"]
    deleted = await call(
        browser,
        administrator,
        "DELETE",
        f"admin/roles/{user['id']}",
        {
            "version": user["version"],
            "reason": "Attempt to remove default role",
        },
    )
    assert deleted.status_code in {403, 404}, deleted.text
    remaining = await call(browser, administrator, "GET", "admin/roles")
    assert any(r["code"] == "user" and r["is_system"] for r in remaining.json())
