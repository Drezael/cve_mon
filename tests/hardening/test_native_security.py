"""Actual authenticated ingress boundaries and read-only optimized database context."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cve_common.database.transactions import transaction
from sqlalchemy import text

from scripts.database.manage import connect
from tests.authorization.integration.conftest import actor
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.hardening


async def test_cookie_shadowing_and_json_ambiguity_fail_before_mutation(browser: Browser) -> None:
    admin = await actor(browser)
    cookie = "__Host-cve-session=" + admin.cookie
    valid = await browser.client.get("/api/v1/auth/session", headers={"cookie": cookie})
    assert valid.status_code == 200
    for headers in [
        [("cookie", cookie), ("cookie", cookie)],
        [("cookie", cookie + "; " + cookie)],
    ]:
        denied = await browser.client.get("/api/v1/auth/session", headers=headers)
        assert denied.status_code == 403
    invalid = await browser.client.post(
        "/api/v1/auth/login",
        content=b'{"username":"one","username":"two"}',
        headers={"content-type": "application/json"},
    )
    assert invalid.status_code == 400
    still_valid = await browser.client.get("/api/v1/auth/session", headers={"cookie": cookie})
    assert still_valid.status_code == 200


async def test_optimized_role_retains_read_only_projection_and_timeouts(browser: Browser) -> None:
    database = browser.service.database
    assert database.engine is not None
    async with database.engine.connect() as connection:
        assert (await connection.execute(text("SHOW jit"))).scalar_one() == "off"
        assert (await connection.execute(text("SHOW statement_timeout"))).scalar_one() == "2s"
    with connect(browser.lab.config, "api_security") as c:
        row = c.execute(
            "SELECT has_table_privilege(current_user,'dashboard.server_list_index','SELECT') AS r,"
            "has_table_privilege(current_user,'dashboard.server_list_index','UPDATE') AS w"
        ).fetchone()
        assert row and row["r"] and not row["w"]


async def test_status_exposes_only_bounded_own_process_metric_aggregates(browser: Browser) -> None:
    from tests.status.test_native import collector

    value = collector(browser)
    try:
        started = datetime.now(UTC)
        observations = await value.gather()
        own = next(o for o in observations if o.service_id == "api" and o.check_id == "readiness")
        assert own.metrics["collector_cpu_seconds"] is not None
        assert own.metrics["collector_rss_bytes"] is not None
        assert own.metrics["api_requests"] is not None
        assert set(own.metrics) <= {
            "collector_cpu_seconds",
            "collector_rss_bytes",
            "api_requests",
            "api_errors",
            "error_rate",
            "api_mean_latency_ms",
        }
        async with transaction(value.database) as session:
            await value.persist(session, observations, started, uuid4())
        with browser.lab.owner() as c:
            row = c.execute(
                "SELECT metrics FROM status.check_observations WHERE service_id='api' "
                "AND check_id='readiness' ORDER BY checked_at DESC LIMIT 1"
            ).fetchone()
            assert row and "collector_rss_bytes" in row["metrics"]
    finally:
        await value.database.close()
