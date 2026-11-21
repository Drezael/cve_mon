"""Administrative recovery requires a second administrator and an independent private handoff."""

from uuid import UUID

import pytest
from cve_api.users.activation import Handoff

from tests.authentication.integration.conftest import Browser
from tests.authentication.integration.test_flows import enroll

from .conftest import actor, call, version

pytestmark = [pytest.mark.authorization, pytest.mark.security]


async def test_admin_recovery_never_exposes_secret_or_grants_password_only_access(
    browser: Browser,
) -> None:
    admin = await actor(browser)
    target = await actor(browser)
    request = await call(
        browser,
        admin,
        "POST",
        f"admin/users/{target.id}/mfa-recovery",
        {"version": version(browser, target.id), "reason": "independently verified request"},
    )
    assert request.status_code == 200, request.text
    assert set(request.json()) == {"request_id", "expires_at", "delivery", "version"}
    assert request.json()["delivery"] == "manual_operator_required"
    assert (await call(browser, target, "GET", "me/permissions")).status_code == 401
    result = await browser.login(target.name, target.password)
    assert result.json()["state"] == "mfa_pending"
    assert (await browser.post("mfa/enroll/start")).status_code == 403
    token = await Handoff(browser.service).issue(target.id, UUID(request.json()["request_id"]))
    result = await browser.post("mfa/recovery/redeem", {"recovery_token": token})
    assert result.status_code == 200 and result.json()["state"] == "mfa_recovery", result.text
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 403
    await enroll(browser)
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 200
    await browser.login(target.name, target.password)
    replay = await browser.post("mfa/recovery/redeem", {"recovery_token": token})
    assert replay.status_code == 401


async def test_user_admin_cannot_request_privileged_mfa_recovery(browser: Browser) -> None:
    admin = await actor(browser)
    manager = await actor(browser, ("user_admin",))
    result = await call(
        browser,
        manager,
        "POST",
        f"admin/users/{admin.id}/mfa-recovery",
        {"version": version(browser, admin.id), "reason": "forged"},
    )
    assert result.status_code == 403


async def test_activation_token_is_single_use_purpose_bound_and_no_email_promised(
    browser: Browser,
) -> None:
    import secrets

    admin = await actor(browser)
    name = "activate-" + secrets.token_hex(4)
    user = await call(
        browser,
        admin,
        "POST",
        "admin/users",
        {"username": name, "email": name + "@example.test", "display_name": "Activation"},
    )
    assert user.status_code == 201, user.text
    uid = UUID(user.json()["id"])
    token = await Handoff(browser.service).issue(uid)
    browser.client.cookies.clear()
    await browser.prepare()
    result = await browser.post(
        "activation/redeem", {"activation_token": token, "new_password": secrets.token_urlsafe(24)}
    )
    assert result.status_code == 204, result.text
    await browser.prepare()
    replay = await browser.post(
        "activation/redeem", {"activation_token": token, "new_password": secrets.token_urlsafe(24)}
    )
    assert replay.status_code == 401
    for route in ("activation/issue", "mfa/recovery/issue", "password/reset"):
        assert (await browser.post(route)).status_code == 404


async def test_recovery_cannot_replace_a_missing_factor_with_password_only_setup(
    browser: Browser,
) -> None:
    admin = await actor(browser)
    viewer = await actor(browser, ("viewer",))
    response = await call(
        browser,
        admin,
        "POST",
        f"admin/users/{viewer.id}/mfa-recovery",
        {"version": version(browser, viewer.id), "reason": "not an enrolled account"},
    )
    assert response.status_code == 409
