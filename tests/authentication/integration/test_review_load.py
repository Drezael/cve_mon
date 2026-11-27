"""Bounded multi-account API workload and revocation, on a disposable PostgreSQL lab."""

import asyncio
import json
import logging
import time
from pathlib import Path
from uuid import UUID

import pytest
from cve_api.auth.sessions import SESSION_COOKIE

from scripts.testing.lock_metrics import summarize
from tests.authentication.integration.conftest import Browser

pytestmark = [pytest.mark.authentication, pytest.mark.performance]


async def test_multi_account_dashboard_reads_and_revocation(
    browser: Browser,
    caplog: pytest.LogCaptureFixture,
) -> None:
    accounts: list[tuple[UUID, str]] = []
    for _ in range(4):
        uid, name, password = await browser.user()
        with browser.lab.owner() as connection:
            connection.execute(
                "INSERT INTO security.user_roles(user_id,role_id) "
                "SELECT %s,id FROM security.roles WHERE code='user' "
                "ON CONFLICT DO NOTHING",
                (uid,),
            )
        assert (await browser.login(name, password)).status_code == 200
        accounts.append((uid, str(browser.client.cookies.get(SESSION_COOKIE))))
    durations = []

    async def read(cookie: str) -> None:
        for _ in range(5):
            start = time.perf_counter()
            response = await browser.client.get(
                "/api/v1/dashboard/security/servers?limit=25",
                headers={"cookie": SESSION_COOKIE + "=" + cookie},
            )
            assert response.status_code == 200, response.text
            durations.append(time.perf_counter() - start)

    with caplog.at_level(logging.INFO, logger="cve.auth.locks"):
        await asyncio.gather(*(read(cookie) for _, cookie in accounts))

    def revoke() -> None:
        with browser.lab.owner() as connection:
            connection.execute("SELECT pg_advisory_xact_lock(909001)")
            connection.execute(
                "UPDATE security.users SET status='disabled',"
                "auth_version=auth_version+1,version=version+1 WHERE id=%s",
                (accounts[0][0],),
            )

    await asyncio.to_thread(revoke)
    denied = await browser.client.get(
        "/api/v1/dashboard/security/servers?limit=25",
        headers={"cookie": SESSION_COOKIE + "=" + accounts[0][1]},
    )
    assert denied.status_code == 401
    records = [
        {
            "event": r.msg,
            "mutation": getattr(r, "mutation", None),
            **({"wait_seconds": r.wait_seconds} if hasattr(r, "wait_seconds") else {}),
            **({"duration_ms": r.duration_ms} if hasattr(r, "duration_ms") else {}),
        }
        for r in caplog.records
    ]
    target = Path(".runtime/test-reports/review-api-load.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "scope": "4 accounts, 20 dashboard reads, empty inventory, ASGI + real PostgreSQL",
                "latency_seconds": sorted(durations),
                "locks": summarize(records),
                "revocation_status": denied.status_code,
            },
            indent=2,
        )
    )
    assert max(durations) < 5, "Bounded smoke workload exceeded the request budget"
