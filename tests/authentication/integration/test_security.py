"""Attack simulations at the HTTP boundary and native PostgreSQL privilege checks."""

import asyncio
import json
import secrets
import statistics
import time
from uuid import uuid4

import psycopg
import pytest
from cve_api.auth.errors import AuthError
from cve_api.auth.reset_tokens import ResetTokens
from cve_api.auth.sessions import SESSION_COOKIE, digest
from cve_common.database.transactions import transaction

from scripts.database import manage as db
from tests.authentication.integration.conftest import Browser
from tests.authentication.integration.test_flows import enroll

pytestmark = [pytest.mark.authentication, pytest.mark.security]


@pytest.mark.parametrize(
    "header,value",
    [
        ("origin", "https://evil.example"),
        ("x-cve-auth-gateway", "forged"),
        ("x-cve-auth-scheme", "http"),
        ("x-real-ip", "not-an-ip"),
        ("host", "api.example.test"),
    ],
)
async def test_spoofed_ingress_or_origin_rejected(
    browser: Browser, header: str, value: str
) -> None:
    await browser.prepare()
    result = await browser.client.post(
        "/api/v1/auth/login",
        json={"username": "unknown", "password": secrets.token_urlsafe(12)},
        headers={header: value, "x-csrf-token": browser.csrf},
    )
    assert result.status_code in (400, 403)
    assert result.headers["cache-control"] == "no-store"


async def test_missing_gateway_and_origin_are_rejected_before_credentials(browser: Browser) -> None:
    await browser.prepare()
    for header in ("x-cve-auth-gateway", "origin"):
        old = browser.client.headers.pop(header)
        result = await browser.post(
            "login", {"username": "unknown", "password": secrets.token_urlsafe(12)}
        )
        browser.client.headers[header] = old
        assert result.status_code == 403
    assert (await browser.client.post("/api/v1/auth/login", content=b"x" * 8193)).status_code == 413


@pytest.mark.parametrize("csrf", ["", "wrong-csrf-token-with-enough-length"])
async def test_csrf_required_for_login_and_authenticated_mutations(
    browser: Browser, csrf: str
) -> None:
    _, name, password = await browser.user()
    await browser.prepare()
    denied = await browser.client.post(
        "/api/v1/auth/login",
        json={"username": name, "password": password},
        headers={"x-csrf-token": csrf},
    )
    assert denied.status_code == 403
    await browser.login(name, password)
    denied = await browser.client.post("/api/v1/auth/logout", headers={"x-csrf-token": csrf})
    assert denied.status_code == 403
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 200


async def test_csrf_is_session_bound_and_tokens_rotate(browser: Browser) -> None:
    _, name, password = await browser.user()
    await browser.login(name, password)
    old_cookie = browser.client.cookies.get(SESSION_COOKIE)
    old_csrf = browser.csrf
    await browser.login(name, password)
    assert browser.csrf != old_csrf
    assert (
        await browser.client.post("/api/v1/auth/logout", headers={"x-csrf-token": old_csrf})
    ).status_code == 403

    assert (
        await browser.client.post(
            "/api/v1/auth/logout",
            headers={
                "cookie": SESSION_COOKIE + "=" + str(old_cookie),
                "x-csrf-token": browser.csrf,
            },
        )
    ).status_code == 403


async def test_authenticated_tabs_share_stable_csrf_until_session_rotates(browser: Browser) -> None:
    _, name, password = await browser.user()
    await browser.login(name, password)
    first = await browser.prepare()
    tab_a = first.json()["csrf_token"]
    tab_b = (await browser.client.get("/api/v1/auth/csrf")).json()["csrf_token"]
    assert tab_a == tab_b
    await asyncio.gather(*(browser.client.get("/api/v1/auth/csrf") for _ in range(3)))
    response = await browser.client.post("/api/v1/auth/logout", headers={"x-csrf-token": tab_a})
    assert response.status_code == 204


async def test_session_fixation_and_fake_identity_headers(browser: Browser) -> None:
    _, name, password = await browser.user(admin=True)
    browser.client.cookies.set(
        SESSION_COOKIE,
        str(uuid4()) + "." + secrets.token_urlsafe(32),
        domain="dashboard.example.test",
        path="/",
    )
    denied = await browser.client.get(
        "/api/v1/auth/_protected",
        headers={"x-user-id": str(uuid4()), "x-role": "admin", "x-forwarded-for": "127.0.0.1"},
    )
    assert denied.status_code == 401
    await browser.login(name, password)
    await enroll(browser)
    await browser.login(name, password)
    assert (
        await browser.client.get("/api/v1/auth/_protected", headers={"x-role": "admin"})
    ).status_code == 403
    # Duplicate cookies cannot shadow the selected server-side identity.
    real = browser.client.cookies.get(SESSION_COOKIE)
    assert (
        await browser.client.get(
            "/api/v1/auth/session",
            headers={"cookie": f"{SESSION_COOKIE}={real}; {SESSION_COOKIE}={real}"},
        )
    ).status_code == 403


async def test_account_enumeration_messages_and_argon_cost(browser: Browser) -> None:
    _, name, _ = await browser.user()
    results = []
    timing = []
    for identity in (name, "unknown-" + uuid4().hex):
        elapsed = []
        for _ in range(4):
            await browser.prepare()
            started = time.monotonic()
            response = await browser.post(
                "login", {"username": identity, "password": secrets.token_urlsafe(24)}
            )
            elapsed.append(time.monotonic() - started)
            data = response.json()
            data.pop("request_id")
            results.append((response.status_code, data))
        timing.append(statistics.median(elapsed))
    assert all(value == results[0] for value in results)
    assert results[0][0] == 401
    # Detect skipped dummy KDFs without treating a shared CI host as a timing oracle.
    assert max(timing) / min(timing) < 5


async def test_persistent_parallel_brute_force_and_spraying_limits(browser: Browser) -> None:
    limits = browser.service.limits
    results = await asyncio.gather(
        *(limits.admit("198.51.100.20", identity="same-account") for _ in range(20)),
        return_exceptions=True,
    )
    assert sum(value is None for value in results) == browser.service.settings.login_limit
    assert all(
        value is None or isinstance(value, AuthError) and value.status == 429 for value in results
    )
    # A fresh limiter instance shares the persisted buckets, across unrelated identities.
    for i in range(60):
        try:
            await limits.admit("198.51.100.21", identity="spray-" + str(i))
        except AuthError as error:
            assert error.status == 429
            break
    else:
        with pytest.raises(AuthError):
            await limits.admit("198.51.100.21", identity="spray-final")
    with browser.lab.owner() as connection:
        rows = connection.execute("SELECT key_hash FROM security.auth_rate_limits").fetchall()
        assert all(len(bytes(r["key_hash"])) == 32 for r in rows)
        count = connection.execute(
            "SELECT n FROM security.auth_counters WHERE name='rate_limited'"
        ).fetchone()["n"]
        assert count > 0


@pytest.mark.parametrize("role", ["api_reader", "importer", "event_dispatcher", "status_probe"])
async def test_native_roles_cannot_read_or_change_credentials_mfa_sessions_or_groups(
    browser: Browser, role: str
) -> None:
    for statement in (
        "SELECT ciphertext FROM security.mfa_methods",
        "UPDATE security.sessions SET revoked_at=clock_timestamp()",
        "UPDATE security.password_credentials SET must_change=true",
        "UPDATE inventory.server_groups SET sort_order=0",
    ):
        with (
            db.connect(browser.lab.config, role) as connection,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            connection.execute(statement)
    with (
        db.connect(browser.lab.config, "api_security") as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(
            "SELECT security.bootstrap_admin('forged','forged@example.test','invalid')"
        )


async def test_audit_outbox_atomicity_and_no_cleartext_verifiers(
    browser: Browser, caplog: pytest.LogCaptureFixture
) -> None:
    uid, name, password = await browser.user(admin=True)
    await browser.login(name, password)
    secret, codes = await enroll(browser)
    cookie = browser.client.cookies.get(SESSION_COOKIE)
    assert cookie is not None
    with browser.lab.owner() as connection:
        session = connection.execute(
            "SELECT verifier,csrf_verifier FROM security.sessions WHERE id=%s",
            (cookie.split(".")[0],),
        ).fetchone()
        assert bytes(session["verifier"]) == digest(cookie.split(".")[1])
        assert bytes(session["csrf_verifier"]) == digest(browser.csrf)
        mfa = connection.execute(
            "SELECT ciphertext FROM security.mfa_methods WHERE user_id=%s AND revoked_at IS NULL",
            (uid,),
        ).fetchone()
        assert secret not in bytes(mfa["ciphertext"])
        events = connection.execute(
            (
                "SELECT payload FROM automation.event_outbox WHERE "
                "event_type='auth.security' AND aggregate_id=%s"
            ),
            (str(uid),),
        ).fetchall()
        audit = connection.execute(
            "SELECT action FROM security.audit_log WHERE actor_user_id=%s", (uid,)
        ).fetchall()
        assert len(events) == len(audit) >= 4
        serialized = json.dumps(events, default=str)
        for value in (password, *codes, str(cookie), browser.csrf):
            assert value not in serialized and value not in caplog.text
    from cve_api.auth.audit import record

    marker = uuid4()
    with pytest.raises(RuntimeError):
        async with transaction(browser.service.database) as session:
            await record(session, "password_changed", uid)
            raise RuntimeError(str(marker))
    with browser.lab.owner() as connection:
        assert (
            connection.execute(
                "SELECT count(*) AS n FROM security.audit_log "
                "WHERE action='auth.password_changed' AND actor_user_id=%s",
                (uid,),
            ).fetchone()["n"]
            == 0
        )
        assert (
            connection.execute(
                "SELECT count(*) AS n FROM automation.event_outbox "
                "WHERE payload->>'action'='password_changed' AND aggregate_id=%s",
                (str(uid),),
            ).fetchone()["n"]
            == 0
        )


async def test_password_reset_is_internal_one_time_and_preserves_mfa(browser: Browser) -> None:
    uid, name, password = await browser.user(admin=True)
    await browser.login(name, password)
    await enroll(browser)
    resets = ResetTokens(browser.service)
    token = await resets.issue(uid, "192.0.2.33")
    replacement = secrets.token_urlsafe(24)
    await resets.consume(token, replacement, "192.0.2.33")
    with pytest.raises(AuthError):
        await resets.consume(token, replacement, "192.0.2.33")
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 401
    assert (await browser.login(name, replacement)).json()["state"] == "mfa_pending"
    for route in (
        "password/reset",
        "password/reset/request",
        "password/reset/confirm",
        "users",
        "bootstrap",
    ):
        assert (await browser.post(route)).status_code == 404


async def test_authentication_responses_match_strict_secret_safe_contract(browser: Browser) -> None:
    from pathlib import Path

    import yaml
    from jsonschema import Draft202012Validator

    root = Path(__file__).resolve().parents[3]
    spec = yaml.safe_load((root / "contracts/api/authentication.openapi.yaml").read_text())
    schema = spec["components"]["schemas"]["AuthenticationResult"]
    validator = Draft202012Validator(schema)
    result = await browser.prepare()
    validator.validate(result.json())
    _, name, password = await browser.user()
    validator.validate((await browser.login(name, password)).json())
    validator.validate((await browser.client.get("/api/v1/auth/session")).json())
    assert password not in result.text
