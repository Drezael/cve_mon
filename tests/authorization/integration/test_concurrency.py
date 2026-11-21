"""Serialized permission mutation and the native last-usable-admin invariant under concurrency."""

import asyncio

import psycopg
import pytest

from scripts.database import manage as db
from tests.authentication.integration.conftest import Browser

from .conftest import actor, call, fresh, role_id, version

pytestmark = [pytest.mark.authorization, pytest.mark.security]


def isolate_administrators(browser: Browser) -> None:
    # Only the migration owner of this disposable database can enter an offline fixture reset.
    with browser.lab.owner() as c:
        c.execute("UPDATE security.administration_state SET armed=false")
        c.execute(
            "UPDATE security.mfa_methods SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL"
        )
        c.execute(
            "UPDATE security.users SET status='disabled',version=version+1 WHERE status='active'"
        )


@pytest.mark.parametrize(
    "action", ["disable", "archive", "lock", "remove_role", "revoke_credentials", "revoke_mfa"]
)
async def test_single_usable_administrator_cannot_be_lost(browser: Browser, action: str) -> None:
    isolate_administrators(browser)
    admin = await actor(browser)
    if action == "remove_role":
        result = await call(
            browser,
            admin,
            "PUT",
            f"admin/users/{admin.id}/roles",
            {"version": version(browser, admin.id), "reason": "self-demotion", "role_ids": []},
        )
        assert result.status_code == 409, result.text
    elif action.startswith("revoke_"):
        table = "password_credentials" if action == "revoke_credentials" else "mfa_methods"
        with (
            db.connect(browser.lab.config, "api_security") as c,
            pytest.raises(psycopg.errors.CheckViolation),
        ):
            c.execute(
                "UPDATE security." + table + " SET revoked_at=clock_timestamp() WHERE user_id=%s",
                (admin.id,),
            )
            c.commit()
    else:
        result = await call(
            browser,
            admin,
            "POST",
            f"admin/users/{admin.id}/{action}",
            {"version": version(browser, admin.id), "reason": "self-disable"},
        )
        assert result.status_code == 409, result.text
    with db.connect(browser.lab.config, "api_security") as c:
        row = c.execute("SELECT security.usable_admin_count() AS n").fetchone()
        assert row is not None and row["n"] == 1
    assert (await call(browser, admin, "GET", "admin/users")).status_code == 200


@pytest.mark.parametrize("action", ["disable", "remove_role"])
async def test_two_administrators_cannot_both_lose_access(browser: Browser, action: str) -> None:
    isolate_administrators(browser)
    first = await actor(browser)
    second = await actor(browser)

    async def mutate(person: object) -> int:
        from .conftest import Actor

        assert isinstance(person, Actor)
        if action == "disable":
            response = await call(
                browser,
                person,
                "POST",
                f"admin/users/{person.id}/disable",
                {"version": version(browser, person.id), "reason": "parallel disable"},
            )
        else:
            response = await call(
                browser,
                person,
                "PUT",
                f"admin/users/{person.id}/roles",
                {
                    "version": version(browser, person.id),
                    "reason": "parallel revoke",
                    "role_ids": [],
                },
            )
        return int(response.status_code)

    results = await asyncio.gather(mutate(first), mutate(second))
    assert sorted(results) == [200, 409], results
    with db.connect(browser.lab.config, "api_security") as c:
        row = c.execute("SELECT security.usable_admin_count() AS n").fetchone()
        assert row is not None and row["n"] == 1


async def test_parallel_roles_optimistic_version_and_one_time_reauth(browser: Browser) -> None:
    admin = await actor(browser)
    target = await actor(browser, ("viewer",))
    body = {
        "version": version(browser, target.id),
        "reason": "race",
        "role_ids": [role_id(browser, "security_analyst")],
    }
    fresh(browser, admin)
    responses = await asyncio.gather(
        *(
            call(browser, admin, "PUT", f"admin/users/{target.id}/roles", body, reauth=False)
            for _ in range(2)
        )
    )
    assert sorted(r.status_code for r in responses) == [200, 403]


async def test_bootstrap_escape_hatch_is_not_available_to_runtime(browser: Browser) -> None:
    with (
        db.connect(browser.lab.config, "api_security") as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("UPDATE security.administration_state SET armed=false")
    with (
        db.connect(browser.lab.config, "api_reader") as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("SELECT * FROM security.administration_state")


async def test_parallel_acl_replacements_preserve_one_complete_revision(browser: Browser) -> None:
    from .test_objects import servers

    first = await actor(browser)
    second = await actor(browser)
    target = await actor(browser, ("viewer",))
    server = servers(browser, 1)[0]
    body = {
        "version": 0,
        "reason": "parallel ACL",
        "grants": [{"user_id": str(target.id), "rights": ["view"]}],
    }
    results = await asyncio.gather(
        call(browser, first, "PUT", f"admin/server-access/{server}", body),
        call(browser, second, "PUT", f"admin/server-access/{server}", body),
    )
    assert sorted(r.status_code for r in results) == [200, 409]
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT version FROM security.server_acl_versions WHERE server_id=%s", (server,)
            ).fetchone()["version"]
            == 1
        )
        assert (
            c.execute(
                "SELECT count(*) AS n FROM security.user_server_access WHERE server_id=%s",
                (server,),
            ).fetchone()["n"]
            == 1
        )


async def test_role_revocation_cannot_be_reused_by_old_or_new_session(browser: Browser) -> None:
    from cve_api.auth.sessions import SESSION_COOKIE
    from cve_api.authorization.administration import Administration
    from cve_api.authorization.errors import Denied

    admin = await actor(browser)
    target = await actor(browser, ("viewer",))
    response = await call(
        browser,
        admin,
        "PUT",
        f"admin/users/{target.id}/roles",
        {"version": version(browser, target.id), "reason": "remove all roles", "role_ids": []},
    )
    assert response.status_code == 200, response.text
    assert (await call(browser, target, "GET", "me/permissions")).status_code == 401
    await browser.login(target.name, target.password)
    cookie = browser.client.cookies.get(SESSION_COOKIE)
    assert cookie
    with pytest.raises(Denied):
        await Administration(browser.service).servers(cookie)
