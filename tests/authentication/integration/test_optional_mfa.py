"""Optional MFA for every role, chosen and removed through authenticated account settings."""

import pytest
from cve_api.auth.totp import code

from tests.authentication.integration.conftest import Browser
from tests.authentication.integration.test_flows import enroll

pytestmark = [pytest.mark.authentication, pytest.mark.security]


async def test_admin_password_only_can_manage_and_choose_mfa(browser: Browser) -> None:
    uid, name, password = await browser.user(admin=True)
    response = await browser.login(name, password)
    assert response.json()["state"] == "authenticated"
    status = (await browser.client.get("/api/v1/auth/session")).json()
    assert not status["mfa_enabled"]
    result = await browser.client.get("/api/v1/dashboard/admin/users")
    assert result.status_code == 200, result.text
    assert (await browser.post("mfa/enroll/start")).status_code == 403
    assert (await browser.post("reauthenticate", {"password": password})).status_code == 200
    start = await browser.post("mfa/enroll/start")
    assert start.status_code == 200 and start.json()["state"] == "authenticated"
    assert (await browser.client.get("/api/v1/auth/session")).json()["mfa_enabled"] is False
    assert (await browser.post("mfa/enroll/cancel")).status_code == 204
    assert (await browser.login(name, password)).json()["state"] == "authenticated"
    secret, _ = await enroll(browser)
    assert (await browser.client.get("/api/v1/auth/session")).json()["mfa_enabled"] is True
    assert (await browser.post("mfa/disable")).status_code == 403
    assert (await browser.post("reauthenticate", {"password": password})).status_code == 401
    response = await browser.post(
        "reauthenticate",
        {
            "password": password,
            "code": code(secret, browser.lab.clock_step() + 1),
        },
    )
    assert response.status_code == 200, response.text
    assert (await browser.post("mfa/disable")).status_code == 200
    assert (await browser.client.get("/api/v1/auth/session")).json()["mfa_enabled"] is False
    assert (await browser.login(name, password)).json()["state"] == "authenticated"
    with browser.lab.owner() as connection:
        assert not connection.execute(
            "SELECT mfa_required FROM security.users WHERE id=%s",
            (uid,),
        ).fetchone()["mfa_required"]
        assert (
            connection.execute(
                "SELECT count(*) n FROM security.recovery_codes WHERE user_id=%s "
                "AND revoked_at IS NULL",
                (uid,),
            ).fetchone()["n"]
            == 0
        )


async def test_password_only_admin_database_commands_and_outage_recovery(browser: Browser) -> None:
    from uuid import uuid4

    from cve_findings.contracts import Policy

    from tests.authorization.integration.test_deployment import (
        test_permissions_survive_restart_and_fail_closed_during_database_outage as restart,
    )

    _, name, password = await browser.user(admin=True)
    await browser.login(name, password)
    body = {
        "label": "optional-mfa-" + uuid4().hex,
        "reason": "Password-only administrator approved policy",
        "configuration": Policy().model_dump(mode="json"),
    }
    headers = {"x-csrf-token": browser.csrf}
    denied = await browser.client.post("/api/v1/findings/policies", json=body, headers=headers)
    assert denied.status_code == 403
    response = await browser.post("reauthenticate", {"password": password})
    assert response.status_code == 200
    approved = await browser.client.post(
        "/api/v1/findings/policies",
        json=body,
        headers={"x-csrf-token": browser.csrf},
    )
    assert approved.status_code == 200, approved.text
    await restart(browser)
