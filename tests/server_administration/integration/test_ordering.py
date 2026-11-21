"Persistent independent scopes, relative moves and optimistic competing administrators."

import asyncio

import pytest

from tests.authentication.integration.conftest import Browser

from .conftest import actor, create_server, send
from .test_lifecycle import tag

pytestmark = [pytest.mark.server_administration, pytest.mark.security]


async def test_parallel_registration_positions_are_distinct(browser: Browser) -> None:
    one, two = await actor(browser), await actor(browser)
    results = await asyncio.gather(create_server(browser, one), create_server(browser, two))
    assert (
        results[0]["id"] != results[1]["id"]
        and results[0]["display_order"] != results[1]["display_order"]
    )


async def test_archive_and_global_order_report_stale_state(browser: Browser) -> None:
    one, two = await actor(browser), await actor(browser)
    s = await create_server(browser, one)
    order = await send(browser, one, "GET", "admin/servers/order")
    results = await asyncio.gather(
        send(
            browser,
            one,
            "POST",
            "admin/servers/" + s["id"] + "/archive",
            {"reason": "race"},
            tag(s),
        ),
        send(
            browser,
            two,
            "PUT",
            "admin/servers/order",
            {"move_id": s["id"], "before_id": None},
            order.headers["etag"],
        ),
    )
    assert sorted(r.status_code for r in results) == [200, 412], [r.text for r in results]
