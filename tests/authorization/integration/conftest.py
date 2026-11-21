"""Reuse the real Phase-8 deployment, credentials and MFA fixtures; only isolated test users."""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from cve_api.auth.sessions import SESSION_COOKIE

from tests.authentication.integration.conftest import Browser
from tests.authentication.integration.conftest import auth_lab as auth_lab
from tests.authentication.integration.conftest import browser as browser
from tests.authentication.integration.test_flows import enroll


@dataclass
class Actor:
    id: UUID
    name: str
    password: str
    cookie: str
    csrf: str


async def actor(browser: Browser, roles: tuple[str, ...] = ("admin",)) -> Actor:
    uid, name, password = await browser.user(admin="admin" in roles)
    with browser.lab.owner() as c:
        for role in roles:
            c.execute(
                (
                    "INSERT INTO security.user_roles(user_id,role_id) SELECT"
                    " %s,id FROM security.roles WHERE code=%s ON CONFLICT DO"
                    " NOTHING"
                ),
                (uid, role),
            )
    result = await browser.login(name, password)
    assert result.status_code == 200, result.text
    if set(roles) & {"admin", "user_admin"}:
        await enroll(browser)
    cookie = browser.client.cookies.get(SESSION_COOKIE)
    assert cookie is not None
    return Actor(uid, name, password, cookie, browser.csrf)


def fresh(browser: Browser, person: Actor) -> None:
    # Fixture-only: model a fresh server-verified MFA reauth. Real HTTP/TOTP is tested separately.
    with browser.lab.owner() as c:
        c.execute(
            (
                "UPDATE security.sessions SET reauthenticated_at=clock_t"
                "imestamp(),reauthentication_consumed_at=NULL WHERE id=%"
                "s"
            ),
            (person.cookie.split(".")[0],),
        )


async def call(
    browser: Browser,
    person: Actor,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    reauth: bool = True,
) -> Any:
    if method != "GET" and reauth:
        fresh(browser, person)
    return await browser.client.request(
        method,
        "/api/v1/dashboard/" + path,
        json=body,
        headers={"cookie": SESSION_COOKIE + "=" + person.cookie, "x-csrf-token": person.csrf},
    )


def version(browser: Browser, uid: UUID) -> int:
    with browser.lab.owner() as c:
        return int(
            c.execute("SELECT version FROM security.users WHERE id=%s", (uid,)).fetchone()[
                "version"
            ]
        )


def role_id(browser: Browser, code: str) -> str:
    with browser.lab.owner() as c:
        return str(
            c.execute("SELECT id FROM security.roles WHERE code=%s", (code,)).fetchone()["id"]
        )
