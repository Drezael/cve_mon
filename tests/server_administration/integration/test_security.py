"ACL before search/count/pagination; no token, field or database-role escalation."

from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from scripts.database.manage import connect
from tests.authentication.integration.conftest import Browser
from tests.database.helpers import snapshot

from .conftest import actor, create_server, send
from .test_lifecycle import tag

pytestmark = [pytest.mark.server_administration, pytest.mark.security]


@pytest.mark.parametrize("roles", [("viewer",), ("security_analyst",), ("user_admin",)])
async def test_non_administrative_roles_cannot_mutate(
    browser: Browser, roles: tuple[str, ...]
) -> None:
    person = await actor(browser, roles)
    attempts: list[tuple[str, str, dict[str, Any]]] = [
        ("POST", "admin/servers", {"display_name": "evil", "request_id": str(uuid4())}),
        ("POST", "admin/groups", {"name": "evil"}),
        ("PUT", "admin/groups/order", {"ids": []}),
        (
            "PUT",
            "admin/servers/" + str(uuid4()) + "/group-assignment",
            {"group_ids": [], "primary_group_id": None},
        ),
    ]
    for method, path, body in attempts:
        r = await send(browser, person, method, path, body, '"1"')
        assert r.status_code == (403 if path == "admin/servers" else 404), r.text


async def test_missing_csrf_reauth_and_rolled_back_audit(browser: Browser) -> None:
    admin = await actor(browser)
    s = await create_server(browser, admin)
    # The registration consumed reauth: it cannot be reused for a second mutation.
    r = await send(
        browser,
        admin,
        "PATCH",
        "admin/servers/" + s["id"],
        {"description": "not applied"},
        tag(s),
        reauth=False,
    )
    assert r.status_code == 403, r.text
    r = await browser.client.post(
        "/api/v1/dashboard/groups",
        json={"name": "csrf", "version": 0},
        headers={"cookie": "__Host-cve-session=" + admin.cookie},
    )
    assert r.status_code == 403
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT description FROM inventory.servers WHERE id=%s", (s["id"],)
            ).fetchone()["description"]
            is None
        )
        audit = c.execute(
            "SELECT id,actor_user_id FROM security.audit_log WHERE a"
            "ction='adm"
            "inistration.server_registered' AND object_id=%s",
            (s["id"],),
        ).fetchone()
        outbox = c.execute(
            "SELECT payload FROM automation.event_outbox WHERE event"
            "_type='adm"
            "inistration.changed' AND aggregate_id=%s",
            (s["id"],),
        ).fetchone()
        assert audit["actor_user_id"] == admin.id and outbox["payload"]["audit_id"] == str(
            audit["id"]
        )


@pytest.mark.parametrize(
    "role",
    [
        "api_ingest",
        "inventory_processor",
        "matcher",
        "importer",
        "enricher",
        "event_dispatcher",
    ],
)
async def test_technical_database_context_cannot_write_administration(
    browser: Browser, role: str
) -> None:
    for sql in [
        "UPDATE inventory.servers SET primary_group_id=NULL",
        "UPDATE inventory.servers SET display_order=0",
        "UPDATE inventory.servers SET criticality='low'",
        "DELETE FROM inventory.server_group_memberships",
        "UPDATE inventory.server_groups SET sort_order=0",
    ]:
        with (
            connect(browser.lab.config, role) as c,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            c.execute(sql)


@pytest.mark.parametrize(
    "field",
    [
        "group_id",
        "group_ids",
        "primary_group_id",
        "group_sort_order",
        "display_order",
        "groupIds",
        "primaryGroupId",
        "displayOrder",
        "primary-group-id",
        "group.sort.order",
        "exposure",
    ],
)
async def test_nested_inventory_control_fields_rejected(browser: Browser, field: str) -> None:
    admin = await actor(browser)
    s = await create_server(browser, admin)
    with browser.lab.owner() as c, pytest.raises(psycopg.errors.CheckViolation):
        snapshot(c, UUID(s["id"]), payload={"nested": [{"further": {field: "forbidden"}}]})


async def test_read_only_diagnostics_find_no_corruption(
    browser: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    from scripts.administration import manage

    monkeypatch.setattr(manage, "load_config", lambda: browser.lab.config)
    monkeypatch.setattr(sys, "argv", ["verify", "all"])
    assert manage.main() == 0
