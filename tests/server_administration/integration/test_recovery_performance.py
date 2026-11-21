"Real restarts, transaction faults, complete workflow and representative PostgreSQL load."

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cve_api.administration.service import InventoryAdministration
from cve_api.auth.repository import execute
from sqlalchemy import event

from scripts.database.manage import connect
from tests.authentication.integration.conftest import Browser

from .conftest import actor, create_server, send

pytestmark = [pytest.mark.server_administration, pytest.mark.security]


async def test_representative_load_acl_query_count_and_relative_order(browser: Browser) -> None:
    admin = await actor(browser)
    viewer = await actor(browser, ("viewer",))
    prefix = "load-" + uuid4().hex[:8]
    with browser.lab.owner() as c:
        groups = c.execute(
            "INSERT INTO inventory.server_groups(name,sort_order,owner_id) SE"
            "LECT %s||n"
            "::text,(SELECT coalesce(max(sort_order),-1) FROM invent"
            "ory.server"
            "_groups)+n,%s FROM generate_series(1,100) n RETURNING id",
            (prefix, viewer.id),
        ).fetchall()
        ids = c.execute(
            "INSERT INTO inventory.servers(display_name,primary_grou"
            "p_id,displ"
            "ay_order) SELECT %s||n::text,%s,(SELECT coalesce(max(di"
            "splay_orde"
            "r),-1) FROM inventory.servers)+n FROM generate_series(1"
            ",2000) n R"
            "ETURNING id",
            (prefix, None),
        ).fetchall()
        server_ids = [r["id"] for r in ids]
        c.execute(
            "INSERT INTO inventory.server_group_memberships(server_i"
            "d,group_id"
            ",display_order) SELECT id,%s,n FROM unnest(%s::uuid[]) "
            "WITH ORDIN"
            "ALITY x(id,n)",
            (groups[0]["id"], server_ids),
        )
        for idx, g in enumerate(groups[1:]):
            c.execute(
                "INSERT INTO inventory.server_group_memberships(server_i"
                "d,group_id"
                ",display_order) SELECT id,%s,n FROM unnest(%s::uuid[]) "
                "WITH ORDIN"
                "ALITY x(id,n)",
                (g["id"], server_ids[idx::99]),
            )
        c.execute(
            "INSERT INTO security.user_server_access(user_id,server_"
            "id,can_rea"
            "d,can_upload) SELECT %s,id,true,false FROM unnest(%s::u"
            "uid[]) x(i"
            "d)",
            (viewer.id, server_ids[:500]),
        )
    service = InventoryAdministration(browser.service)
    database = browser.service.administration_database
    assert database is not None and database.engine is not None
    queries = []

    def counted(*args: object) -> None:
        queries.append(1)

    event.listen(database.engine.sync_engine, "before_cursor_execute", counted)
    try:
        await service.list_servers(viewer.cookie, limit=1, search=prefix)
        one = len(queries)
        queries.clear()
        page = await service.list_servers(viewer.cookie, limit=100, search=prefix)
        hundred = len(queries)
        assert page["total"] == 500 and len(page["items"]) == 100 and one == hundred
    finally:
        event.remove(database.engine.sync_engine, "before_cursor_execute", counted)
    started = time.monotonic()
    # Match the fixture's fixed pool of three database connections; exercise
    # all 24 pages through bounded workers rather than timing pool admission.
    slots = asyncio.Semaphore(3)

    async def load_page(offset: int) -> dict[str, Any]:
        async with slots:
            return await service.list_servers(viewer.cookie, limit=25, offset=offset, search=prefix)

    pages = await asyncio.gather(*(load_page(i) for i in range(24)))
    seconds = time.monotonic() - started
    assert all(p["total"] == 500 for p in pages)
    order = await send(browser, admin, "GET", "admin/servers/order")
    moved = await send(
        browser,
        admin,
        "PUT",
        "admin/servers/order",
        {"move_id": str(server_ids[-1]), "before_id": str(server_ids[0])},
        order.headers["etag"],
    )
    assert moved.status_code == 200, moved.text
    with browser.lab.owner() as c:
        plan = c.execute(
            "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT server_id "
            "FROM secur"
            "ity.user_server_access WHERE user_id=%s AND can_read OR"
            "DER BY ser"
            "ver_id LIMIT 25",
            (viewer.id,),
        ).fetchone()["QUERY PLAN"]
    target = Path(".runtime/test-reports/phase-10-performance.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "servers": 2000,
                "groups": 100,
                "memberships": 4000,
                "grants": 500,
                "requests": 24,
                "concurrency": 3,
                "seconds": seconds,
                "queries_per_page": one,
                "plan": plan,
            },
            indent=2,
        )
    )
    target.chmod(0o600)


async def test_real_database_connection_loss_rolls_back(browser: Browser) -> None:
    from cve_api.auth.repository import one
    from sqlalchemy.exc import DBAPIError

    from tests.authorization.integration.conftest import fresh

    admin = await actor(browser)
    s = await create_server(browser, admin)
    fresh(browser, admin)
    with pytest.raises(DBAPIError):
        async with InventoryAdministration(browser.service).operation(
            admin.cookie, admin.csrf, "server:update", mutation=True
        ) as (tx, _):
            await execute(
                tx,
                "UPDATE inventory.servers SET description='uncommitted',"
                "version=version+1 WHERE id=:sid",
                sid=s["id"],
            )
            pid = await one(tx, "SELECT pg_backend_pid() AS pid")
            assert pid is not None
            with connect(browser.lab.config, "dashboard_admin") as c:
                c.execute("SELECT pg_terminate_backend(%s)", (pid["pid"],))
            await execute(tx, "SELECT 1")
    r = await send(browser, admin, "GET", "servers/" + s["id"])
    assert (
        r.status_code == 200
        and r.json()["description"] is None
        and r.json()["version"] == s["version"]
    )
