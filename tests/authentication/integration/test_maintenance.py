"""Bounded expiry cleanup, immutable recent history and authorized archived retention."""

from uuid import uuid4

import psycopg
import pytest
from cve_api.auth.sessions import SESSION_COOKIE

from scripts.database import manage as db
from tests.authentication.integration.conftest import Browser

pytestmark = [pytest.mark.authentication, pytest.mark.security]


async def test_expired_sessions_are_pruned_in_bounded_maintenance(browser: Browser) -> None:
    _, name, password = await browser.user()
    await browser.login(name, password)
    token = browser.client.cookies.get(SESSION_COOKIE)
    assert token is not None
    with browser.lab.owner() as connection:
        connection.execute(
            "UPDATE security.sessions SET created_at=statement_timestamp()-interval '40 days',"
            "expires_at=statement_timestamp()-interval '39 days',"
            "idle_expires_at=statement_timestamp()-interval '39 days' WHERE id=%s",
            (token.split(".")[0],),
        )
    with db.connect(browser.lab.config, "api_security") as connection:
        connection.execute("SELECT security.auth_cleanup()")
    assert (await browser.client.get("/api/v1/auth/session")).status_code == 401
    with browser.lab.owner() as connection:
        assert (
            connection.execute(
                "SELECT count(*) AS n FROM security.sessions WHERE id=%s", (token.split(".")[0],)
            ).fetchone()["n"]
            == 0
        )
    assert await browser.service.ready()


async def test_history_retention_requires_operator_and_preserves_recent_and_legacy(
    browser: Browser,
) -> None:
    old, recent, legacy = uuid4(), uuid4(), uuid4()
    with browser.lab.owner() as connection:
        for uid, expired, managed in (
            (old, True, True),
            (recent, False, True),
            (legacy, True, False),
        ):
            connection.execute(
                "INSERT INTO security.audit_log(id,action,object_type,outcome,"
                "auth_runtime,occurred_at) "
                "VALUES(%s,'auth.retention_fixture','test','success',%s,clock_timestamp()-"
                "CASE WHEN %s THEN interval '91 days' ELSE interval '1 day' END)",
                (uid, managed, expired),
            )
    with (
        db.connect(browser.lab.config, "api_security") as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute("SELECT security.auth_purge_archived(%s)", (uuid4(),))
    with browser.lab.owner() as connection, pytest.raises(psycopg.errors.InsufficientPrivilege):
        connection.execute("DELETE FROM security.audit_log WHERE id=%s", (recent,))
    with db.connect(browser.lab.config, "cve_migrator") as connection:
        row = connection.execute(
            "SELECT security.auth_purge_archived(%s) AS report", (uuid4(),)
        ).fetchone()
        assert row is not None
        report = row["report"]
        assert report["audit_rows"] == 1
    with browser.lab.owner() as connection:
        remaining = {
            row["id"]
            for row in connection.execute(
                "SELECT id FROM security.audit_log WHERE id=ANY(%s)", ([old, recent, legacy],)
            ).fetchall()
        }
        assert remaining == {recent, legacy}


async def test_lost_or_wrong_enrollment_context_never_enables_mfa(browser: Browser) -> None:
    from cve_api.auth.totp import code

    from tests.authentication.integration.test_flows import enroll

    _, name, password = await browser.user(admin=True)
    await browser.login(name, password)
    secret, _ = await enroll(browser)
    await browser.login(name, password)
    # Successful enrollment consumed the current time step; a future-outside-window OTP fails.
    assert (
        await browser.post("mfa/verify", {"code": code(secret, browser.lab.clock_step() + 10)})
    ).status_code == 401
    assert (await browser.post("mfa/enroll/start")).status_code == 403
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 403
