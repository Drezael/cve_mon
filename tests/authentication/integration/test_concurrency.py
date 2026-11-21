"""Real concurrent consumption/rotation, stale contexts and credential invalidation."""

import asyncio
import secrets

import pytest
from cve_api.auth.errors import AuthError
from cve_api.auth.reset_tokens import ResetTokens
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.auth.totp import code

from tests.authentication.integration.conftest import Browser
from tests.authentication.integration.test_flows import enroll

pytestmark = [pytest.mark.authentication, pytest.mark.security]


async def test_parallel_totp_code_only_once(browser: Browser) -> None:
    _, name, password = await browser.user(admin=True)
    await browser.login(name, password)
    secret, _ = await enroll(browser)
    await browser.login(name, password)
    value = code(secret, browser.lab.clock_step() + 1)
    old = browser.client.cookies.get(SESSION_COOKIE)
    csrf = browser.csrf
    results = await asyncio.gather(
        *(
            browser.client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": value},
                headers={"cookie": SESSION_COOKIE + "=" + str(old), "x-csrf-token": csrf},
            )
            for _ in range(8)
        )
    )
    assert sum(r.status_code == 200 for r in results) == 1
    assert all(r.status_code in (200, 401, 429) for r in results)


async def test_parallel_recovery_only_once_and_no_full_context(browser: Browser) -> None:
    _, name, password = await browser.user(admin=True)
    await browser.login(name, password)
    _, codes = await enroll(browser)
    await browser.login(name, password)
    old = browser.client.cookies.get(SESSION_COOKIE)
    csrf = browser.csrf
    results = await asyncio.gather(
        *(
            browser.client.post(
                "/api/v1/auth/mfa/recovery",
                json={"code": codes[0]},
                headers={"cookie": SESSION_COOKIE + "=" + str(old), "x-csrf-token": csrf},
            )
            for _ in range(8)
        )
    )
    winners = [r for r in results if r.status_code == 200]
    assert len(winners) == 1
    assert winners[0].json()["state"] == "mfa_recovery"
    with browser.lab.owner() as connection:
        rows = connection.execute(
            "SELECT used_at FROM security.recovery_codes WHERE verifier=%s",
            (__import__("hashlib").sha256(codes[0].encode()).digest(),),
        ).fetchall()
        assert len(rows) == 1 and rows[0]["used_at"] is not None


async def test_parallel_reset_token_only_once(browser: Browser) -> None:
    uid, _, _ = await browser.user()
    resets = ResetTokens(browser.service)
    token = await resets.issue(uid, "192.0.2.70")
    replacement = secrets.token_urlsafe(24)
    results = await asyncio.gather(
        *(resets.consume(token, replacement, "192.0.2.70") for _ in range(4)),
        return_exceptions=True,
    )
    assert sum(r is None for r in results) == 1
    assert all(r is None or isinstance(r, AuthError) for r in results)
    with browser.lab.owner() as connection:
        assert (
            connection.execute(
                "SELECT credential_version FROM security.password_credentials WHERE user_id=%s",
                (uid,),
            ).fetchone()["credential_version"]
            == 2
        )


async def test_parallel_reauthentication_rotates_exactly_one_old_session(browser: Browser) -> None:
    _, name, password = await browser.user()
    await browser.login(name, password)
    old = browser.client.cookies.get(SESSION_COOKIE)
    csrf = browser.csrf
    results = await asyncio.gather(
        *(
            browser.client.post(
                "/api/v1/auth/reauthenticate",
                json={"password": password},
                headers={"cookie": SESSION_COOKIE + "=" + str(old), "x-csrf-token": csrf},
            )
            for _ in range(4)
        )
    )
    assert sum(r.status_code == 200 for r in results) == 1
    assert all(r.status_code in (200, 401) for r in results)
    assert (
        await browser.client.get(
            "/api/v1/auth/session", headers={"cookie": SESSION_COOKIE + "=" + str(old)}
        )
    ).status_code == 401


async def test_password_change_racing_validation_never_leaves_old_session_valid(
    browser: Browser,
) -> None:
    _, name, password = await browser.user()
    await browser.login(name, password)
    await browser.post("reauthenticate", {"password": password})
    old = browser.client.cookies.get(SESSION_COOKIE)
    result = await asyncio.gather(
        browser.post(
            "password/change", {"password": password, "new_password": secrets.token_urlsafe(24)}
        ),
        *(browser.client.get("/api/v1/auth/_protected") for _ in range(8)),
    )
    assert result[0].status_code == 204
    assert all(r.status_code in (200, 401) for r in result[1:])
    assert (
        await browser.client.get(
            "/api/v1/auth/_protected", headers={"cookie": SESSION_COOKIE + "=" + str(old)}
        )
    ).status_code == 401


@pytest.mark.parametrize("kind", ["expired", "tampered", "wrong_purpose", "weak", "expected_name"])
async def test_invalid_reset_tokens_never_change_credentials(browser: Browser, kind: str) -> None:
    uid, name, password = await browser.user()
    resets = ResetTokens(browser.service)
    token = await resets.issue(uid, "192.0.2.71")
    if kind == "expired":
        with browser.lab.owner() as connection:
            connection.execute(
                (
                    "UPDATE security.account_tokens SET created_at=cloc"
                    "k_timestamp()-interval '2 hours',expires_at=clock_"
                    "timestamp()-interval '1 hour' WHERE id=%s"
                ),
                (token.split(".")[0],),
            )
    elif kind == "wrong_purpose":
        with browser.lab.owner() as connection:
            connection.execute(
                "UPDATE security.account_tokens SET purpose='activation' WHERE id=%s",
                (token.split(".")[0],),
            )
    elif kind == "tampered":
        token = token[:-1] + ("A" if token[-1] != "A" else "B")
    replacement = (
        "short"
        if kind == "weak"
        else name
        if kind == "expected_name"
        else secrets.token_urlsafe(24)
    )
    with pytest.raises(AuthError):
        await resets.consume(token, replacement, "192.0.2.71")
    assert (await browser.login(name, password)).status_code == 200


async def test_mfa_change_requires_fresh_one_use_reauth(browser: Browser) -> None:
    _, name, password = await browser.user(admin=True)
    await browser.login(name, password)
    secret, _ = await enroll(browser)
    assert (await browser.post("mfa/enroll/start")).status_code == 403
    assert (await browser.post("reauthenticate", {"password": password})).status_code == 401
    response = await browser.post(
        "reauthenticate", {"password": password, "code": code(secret, browser.lab.clock_step() + 1)}
    )
    assert response.status_code == 200, response.text
    reauth_cookie = browser.client.cookies.get(SESSION_COOKIE)
    start = await browser.post("mfa/enroll/start")
    assert start.status_code == 200 and start.json()["state"] == "authenticated"
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 200
    assert (
        await browser.client.get(
            "/api/v1/auth/session", headers={"cookie": SESSION_COOKIE + "=" + str(reauth_cookie)}
        )
    ).status_code == 200
