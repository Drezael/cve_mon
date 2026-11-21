"""Mutation/audit/outbox atomicity and no partial ACL changes after rejection."""

import secrets
from uuid import UUID, uuid4

import pytest
from cve_api.auth.repository import one
from cve_api.authorization.administration import Administration
from cve_api.authorization.audit import record

from tests.authentication.integration.conftest import Browser

from .conftest import actor, call, fresh
from .test_objects import servers

pytestmark = [pytest.mark.authorization, pytest.mark.security]


async def test_actor_target_and_outbox_share_commit_and_rollback(browser: Browser) -> None:
    admin = await actor(browser)
    name = "audited-" + secrets.token_hex(5)
    created = await call(
        browser,
        admin,
        "POST",
        "admin/users",
        {"username": name, "email": name + "@example.test", "display_name": "Audited"},
    )
    assert created.status_code == 201
    uid = UUID(created.json()["id"])
    with browser.lab.owner() as c:
        audit = c.execute(
            (
                "SELECT actor_user_id,object_id,outcome FROM security.au"
                "dit_log WHERE action='authorization.user_created' AND o"
                "bject_id=%s"
            ),
            (str(uid),),
        ).fetchone()
        event = c.execute(
            (
                "SELECT payload FROM automation.event_outbox WHERE event"
                "_type='authorization.security' AND payload->>'action'='"
                "user_created' AND aggregate_id=%s"
            ),
            (str(uid),),
        ).fetchone()
        assert (
            audit["actor_user_id"] == admin.id
            and audit["object_id"] == str(uid)
            and audit["outcome"] == "success"
        )
        assert event["payload"]["actor_id"] == str(admin.id) and event["payload"][
            "target_id"
        ] == str(uid)
    marker = "rollback-" + secrets.token_hex(5)
    fresh(browser, admin)
    with pytest.raises(RuntimeError):
        async with Administration(browser.service).operation(
            admin.cookie, admin.csrf, "user:create", mutation=True
        ) as (s, a, _):
            row = await one(
                s,
                (
                    "INSERT INTO security.users(username,email,display_name)"
                    " VALUES(:n,:e,:n) RETURNING id"
                ),
                n=marker,
                e=marker + "@example.test",
            )
            assert row is not None
            await record(s, "user_created", a.user_id, row["id"])
            raise RuntimeError("fault injection")
    with browser.lab.owner() as c:
        assert (
            c.execute(
                ("SELECT count(*) AS n FROM security.users WHERE username=%s"), (marker,)
            ).fetchone()["n"]
            == 0
        )


async def test_invalid_acl_batch_rolls_back_and_does_not_revoke_existing_grantee(
    browser: Browser,
) -> None:
    admin = await actor(browser)
    viewer = await actor(browser, ("viewer",))
    server = servers(browser, 1)[0]
    failed = await call(
        browser,
        admin,
        "PUT",
        f"admin/server-access/{server}",
        {
            "version": 0,
            "reason": "partial invalid batch",
            "grants": [
                {"user_id": str(viewer.id), "rights": ["view"]},
                {"user_id": str(uuid4()), "rights": ["view"]},
            ],
        },
    )
    assert failed.status_code == 422, failed.text
    with browser.lab.owner() as c:
        assert (
            c.execute(
                ("SELECT count(*) AS n FROM security.user_server_access WHERE server_id=%s"),
                (server,),
            ).fetchone()["n"]
            == 0
        )
        assert (
            c.execute(
                ("SELECT count(*) AS n FROM security.server_acl_versions WHERE server_id=%s"),
                (server,),
            ).fetchone()["n"]
            == 0
        )
    assert (await call(browser, viewer, "GET", "me/permissions")).status_code == 200
