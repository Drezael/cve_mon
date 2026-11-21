"""Representative ACL filtering with bounded SQL query count and real PostgreSQL plans."""

import asyncio
import json
import time
from pathlib import Path

import pytest
from cve_api.authorization.administration import Administration
from sqlalchemy import event

from tests.authentication.integration.conftest import Browser

from .conftest import actor

pytestmark = [pytest.mark.authorization, pytest.mark.security]


async def test_filtered_pagination_is_indexed_and_query_count_does_not_grow(
    browser: Browser,
) -> None:
    viewer = await actor(browser, ("viewer",))
    prefix = "bench-" + str(viewer.id)
    with browser.lab.owner() as c:
        c.execute(
            (
                "INSERT INTO security.users(username,email,display_name)"
                " SELECT %s||i,%s||i||'@example.test','benchmark' FROM g"
                "enerate_series(1,1000) i"
            ),
            (prefix, prefix),
        )
        c.execute(
            (
                "INSERT INTO security.roles(code,name) SELECT 'bench_'||"
                "substr(md5(%s||i),1,20),%s||i FROM generate_series(1,20"
                "0) i"
            ),
            (prefix, prefix),
        )
        ids = [
            r["id"]
            for r in c.execute(
                (
                    "INSERT INTO inventory.servers(display_name,inventory_ho"
                    "stname,inventory_name) SELECT %s||i,%s||i,%s||i FROM ge"
                    "nerate_series(1,4000) i RETURNING id"
                ),
                (prefix, prefix, prefix),
            ).fetchall()
        ]
        for uid in ids[::8]:
            c.execute(
                (
                    "INSERT INTO security.user_server_access(user_id,server_"
                    "id,can_read) VALUES(%s,%s,true)"
                ),
                (viewer.id, uid),
            )
        c.execute("ANALYZE inventory.servers")
        c.execute("ANALYZE security.user_server_access")
        plan = c.execute(
            (
                "EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) SELECT s.id FROM i"
                "nventory.servers s WHERE s.status<>'archived' AND EXIST"
                "S(SELECT 1 FROM security.user_server_access a WHERE a.s"
                "erver_id=s.id AND a.user_id=%s AND a.can_read) ORDER BY"
                " s.id LIMIT 25"
            ),
            (viewer.id,),
        ).fetchone()["QUERY PLAN"]
    api = Administration(browser.service)
    engine = browser.service.database.engine
    assert engine is not None
    statements = []

    def counted(*args: object) -> None:
        statements.append(1)

    event.listen(engine.sync_engine, "before_cursor_execute", counted)
    try:
        a = await api.servers(viewer.cookie, search=prefix, limit=1)
        first_count = len(statements)
        statements.clear()
        b = await api.servers(viewer.cookie, search=prefix, limit=100)
        second_count = len(statements)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", counted)
    assert a["total"] == b["total"] == 500
    assert len(a["items"]) == 1 and len(b["items"]) == 100
    assert first_count == second_count and first_count <= 15
    started = time.monotonic()
    results = await asyncio.gather(
        *(api.servers(viewer.cookie, search=prefix, limit=25) for _ in range(24))
    )
    duration = time.monotonic() - started
    assert all(r["total"] == 500 for r in results) and duration < 30
    assert "Index" in json.dumps(plan)
    report = {
        "seed_users": 1000,
        "seed_roles": 200,
        "seed_servers": 4000,
        "explicit_grants": 500,
        "concurrent_queries": 24,
        "seconds": duration,
        "sql_queries_per_page": first_count,
        "query_plan": plan,
    }
    target = Path(".runtime/test-reports/phase-09-performance.json")
    target.write_text(json.dumps(report, indent=2))
