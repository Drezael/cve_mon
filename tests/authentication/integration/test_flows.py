"""Full state transitions, revoked contexts and MFA enrollment on a real database."""

import base64
from urllib.parse import parse_qs, urlsplit

import pytest
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.auth.totp import code

from tests.authentication.integration.conftest import Browser

pytestmark = [pytest.mark.authentication, pytest.mark.security]


async def enroll(browser: Browser) -> tuple[bytes, list[str]]:
    status = (await browser.client.get("/api/v1/auth/session")).json()
    if status["state"] == "authenticated" and not status["mfa_enabled"]:
        response = await browser.post("reauthenticate", {"password": browser.login_password})
        assert response.status_code == 200, response.text
    start = await browser.post("mfa/enroll/start")
    assert start.status_code == 200, start.text
    encoded = parse_qs(urlsplit(start.json()["provisioning_uri"]).query)["secret"][0]
    secret = base64.b32decode(encoded + "=" * ((-len(encoded)) % 8))
    confirm = await browser.post(
        "mfa/enroll/confirm", {"code": code(secret, browser.lab.clock_step())}
    )
    assert confirm.status_code == 200, confirm.text
    assert confirm.json()["state"] == "authenticated"
    return secret, confirm.json()["recovery_codes"]


async def test_admin_full_mfa_enrollment_and_session_rotation(browser: Browser) -> None:
    _, name, password = await browser.user(admin=True)
    response = await browser.login(name, password)
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "authenticated"
    pending = browser.client.cookies.get(SESSION_COOKIE)
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 200
    secret, codes = await enroll(browser)
    assert len(codes) == 10 and len(set(codes)) == 10
    assert browser.client.cookies.get(SESSION_COOKIE) != pending
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 200
    denied = await browser.client.get(
        "/api/v1/auth/_protected", headers={"cookie": SESSION_COOKIE + "=" + str(pending)}
    )
    assert denied.status_code == 401
    cookie = browser.client.cookies.get(SESSION_COOKIE)
    logout = await browser.post("logout")
    assert logout.status_code == 204
    assert (
        await browser.client.get(
            "/api/v1/auth/session", headers={"cookie": SESSION_COOKIE + "=" + str(cookie)}
        )
    ).status_code == 401
    assert (await browser.login(name, password)).json()["state"] == "mfa_pending"
    # Enrollment consumed the current step. Replay is denied even in a new password challenge.
    assert (
        await browser.post("mfa/verify", {"code": code(secret, browser.lab.clock_step())})
    ).status_code == 401
    good = await browser.post("mfa/verify", {"code": code(secret, browser.lab.clock_step() + 1)})
    assert good.status_code == 200, good.text


async def test_regular_login_secure_cookie_and_logout_all(browser: Browser) -> None:
    _, name, password = await browser.user()
    result = await browser.login(name, password)
    assert result.status_code == 200 and result.json()["state"] == "authenticated"
    header = next(
        h for h in result.headers.get_list("set-cookie") if h.startswith(SESSION_COOKIE + "=")
    )
    assert all(
        value in header.lower() for value in ("secure", "httponly", "samesite=strict", "path=/")
    )
    assert "domain=" not in header.lower()
    assert "cookie" not in result.json()
    first = browser.client.cookies.get(SESSION_COOKIE)
    assert (await browser.login(name, password)).status_code == 200
    second = browser.client.cookies.get(SESSION_COOKIE)
    assert first != second
    assert (
        await browser.client.get(
            "/api/v1/auth/session", headers={"cookie": SESSION_COOKIE + "=" + str(first)}
        )
    ).status_code == 200
    assert (await browser.post("logout-all")).status_code == 204
    for old in (first, second):
        assert (
            await browser.client.get(
                "/api/v1/auth/session", headers={"cookie": SESSION_COOKIE + "=" + str(old)}
            )
        ).status_code == 401


@pytest.mark.parametrize("status", ["locked", "disabled", "archived", "pending_activation"])
async def test_inactive_accounts_never_login(browser: Browser, status: str) -> None:
    _, name, password = await browser.user(status=status)
    result = await browser.login(name, password)
    assert result.status_code == 401
    assert result.json()["code"] == "UNAUTHENTICATED"
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 401


@pytest.mark.parametrize("admin", [True, False])
async def test_recovery_requires_password_and_leads_to_restricted_reenrollment(
    browser: Browser,
    admin: bool,
) -> None:
    _, name, password = await browser.user(admin=admin)
    await browser.login(name, password)
    if not admin:
        assert (await browser.post("reauthenticate", {"password": password})).status_code == 200
    _, codes = await enroll(browser)
    assert (await browser.post("mfa/recovery", {"code": codes[0]})).status_code == 403
    await browser.login(name, password)
    old = browser.client.cookies.get(SESSION_COOKIE)
    result = await browser.post("mfa/recovery", {"code": codes[0]})
    assert result.status_code == 200 and result.json()["state"] == "mfa_recovery"
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 403
    assert (
        await browser.client.get(
            "/api/v1/auth/session", headers={"cookie": SESSION_COOKIE + "=" + str(old)}
        )
    ).status_code == 401
    recovery_cookie = browser.client.cookies.get(SESSION_COOKIE)
    recovery_csrf = browser.csrf
    assert (await browser.login(name, password)).json()["state"] == "mfa_pending"
    assert (await browser.post("mfa/enroll/start")).status_code == 403
    browser.client.cookies.clear()
    assert recovery_cookie is not None
    browser.client.cookies.set(
        SESSION_COOKIE, recovery_cookie, domain="dashboard.example.test", path="/"
    )
    browser.csrf = recovery_csrf
    _, new_codes = await enroll(browser)
    assert set(codes).isdisjoint(new_codes)
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 200


async def test_password_change_requires_fresh_reauth_and_revokes_every_session(
    browser: Browser,
) -> None:
    import secrets

    uid, name, password = await browser.user()
    await browser.login(name, password)
    first = browser.client.cookies.get(SESSION_COOKIE)
    replacement = secrets.token_urlsafe(24)
    denied = await browser.post(
        "password/change", {"password": password, "new_password": replacement}
    )
    assert denied.status_code == 403
    assert (await browser.post("reauthenticate", {"password": password})).status_code == 200
    fresh = browser.client.cookies.get(SESSION_COOKIE)
    assert fresh != first
    assert (
        await browser.post("password/change", {"password": password, "new_password": replacement})
    ).status_code == 204
    for token in (first, fresh):
        assert (
            await browser.client.get(
                "/api/v1/auth/session", headers={"cookie": SESSION_COOKIE + "=" + str(token)}
            )
        ).status_code == 401
    assert (await browser.login(name, password)).status_code == 401
    assert (await browser.login(name, replacement)).status_code == 200
    with browser.lab.owner() as connection:
        assert (
            connection.execute(
                "SELECT credential_version FROM security.password_credentials WHERE user_id=%s",
                (uid,),
            ).fetchone()["credential_version"]
            == 2
        )


@pytest.mark.parametrize(
    "field",
    [
        "idle_expires_at",
        "expires_at",
        "revoked_at",
        "auth_version",
        "account_status",
        "credential_version",
    ],
)
async def test_session_expiry_and_security_revocation(browser: Browser, field: str) -> None:
    uid, name, password = await browser.user()
    await browser.login(name, password)
    token = browser.client.cookies.get(SESSION_COOKIE)
    assert token is not None
    sid = token.split(".")[0]
    with browser.lab.owner() as connection:
        if field == "account_status":
            connection.execute(
                "UPDATE security.users SET status='disabled',version=version+1 WHERE id=%s", (uid,)
            )
        elif field == "auth_version":
            connection.execute(
                (
                    "UPDATE security.users SET auth_version=auth_versio"
                    "n+1,version=version+1 WHERE id=%s"
                ),
                (uid,),
            )
        elif field == "credential_version":
            connection.execute(
                (
                    "UPDATE security.password_credentials SET credentia"
                    "l_version=credential_version+1 WHERE user_id=%s"
                ),
                (uid,),
            )
        elif field == "revoked_at":
            connection.execute(
                "UPDATE security.sessions SET revoked_at=clock_timestamp() WHERE id=%s", (sid,)
            )
        else:
            # Move creation into the past too, preserving existing Phase-3 time constraints.
            connection.execute(
                (
                    "UPDATE security.sessions SET created_at=clock_time"
                    "stamp()-interval '2 hours',idle_expires_at=clock_t"
                    "imestamp()-interval '1 second' WHERE id=%s"
                ),
                (sid,),
            )
            if field == "expires_at":
                connection.execute(
                    (
                        "UPDATE security.sessions SET expires_at=clock_time"
                        "stamp()-interval '1 second',idle_expires_at=clock_"
                        "timestamp()-interval '2 seconds' WHERE id=%s"
                    ),
                    (sid,),
                )
    assert (await browser.client.get("/api/v1/auth/session")).status_code == 401


async def test_reactivated_account_cannot_reuse_revoked_session(browser: Browser) -> None:
    uid, name, password = await browser.user()
    await browser.login(name, password)
    with browser.lab.owner() as connection:
        connection.execute(
            "UPDATE security.users SET status='disabled',version=version+1 WHERE id=%s", (uid,)
        )
        connection.execute(
            "UPDATE security.users SET status='active',version=version+1 WHERE id=%s", (uid,)
        )
    assert (await browser.client.get("/api/v1/auth/session")).status_code == 401
    assert (await browser.login(name, password)).status_code == 200
