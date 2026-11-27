"""Current-source contention with real PostgreSQL, HTTP, KDF, inventory and matching jobs."""

import asyncio
import json
import logging
import os
import platform
import resource
import secrets
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from scripts.hardening.metrics import distribution
from scripts.testing.source import identity
from tests.authorization.integration.conftest import actor, call
from tests.findings.test_native import Harness
from tests.inventory_processor.test_processing import drain
from tests.inventory_upload.integration.test_discovery import upload, uploader
from tests.matching.test_container_inventory import inventory

pytestmark = pytest.mark.hardening


async def test_review_contention_and_shared_bill_workload(harness: Harness, caplog: Any) -> None:
    browser = harness.browser
    root = browser.lab.config.root
    source = identity(root)
    from sqlalchemy import event

    query_errors: list[dict[str, Any]] = []

    def error_seen(context: Any) -> None:
        query_errors.append(
            {
                "exception": type(context.original_exception).__name__,
                "sqlstate": getattr(context.original_exception, "sqlstate", None),
                "statement": str(context.statement)[:240],
            }
        )

    assert browser.service.database.engine is not None
    event.listen(browser.service.database.engine.sync_engine, "handle_error", error_seen)
    caplog.set_level(logging.INFO, logger="cve.auth.locks")
    person = await actor(browser, ("user",))
    second = await actor(browser, ("user",))
    reader = await actor(browser, ("user",))
    password = secrets.token_urlsafe(24)
    latencies: list[float] = []
    statuses: list[int] = []
    gate = asyncio.Semaphore(3)

    async def read() -> None:
        async with gate:
            began = time.perf_counter()
            response = await call(browser, reader, "GET", "me/ansible-vault")
            latencies.append((time.perf_counter() - began) * 1000)
            statuses.append(response.status_code)

    began = time.perf_counter()
    vault, parallel_vault, _ = await asyncio.gather(
        call(
            browser,
            person,
            "PUT",
            "me/ansible-vault",
            {"password": password, "password_confirmation": password},
        ),
        call(
            browser,
            second,
            "PUT",
            "me/ansible-vault",
            {"password": password, "password_confirmation": password},
        ),
        asyncio.gather(*(read() for _ in range(30))),
    )
    vault_with_reads_ms = (time.perf_counter() - began) * 1000
    assert vault.status_code == 200, vault.text
    assert parallel_vault.status_code == 200, parallel_vault.text
    assert statuses == [200] * 30, query_errors
    assert max(latencies) < 5000

    await uploader(browser)
    document = inventory()
    base = document["container_software"]["items"][0]
    base["document"]["packages"] = [
        {"name": f"library-{i}", "version": "1.0.0", "type": "npm"} for i in range(500)
    ]
    container = document["containers"]["items"][0]
    document["containers"]["items"] = [
        {**container, "container_id": f"container-{i}"} for i in range(20)
    ]
    document["container_software"]["items"] = [
        {**base, "container_id": f"container-{i}"} for i in range(20)
    ]
    began = time.perf_counter()
    response = await upload(browser, document)
    assert response.status_code == 202, response.text
    await drain(browser)
    await harness.matcher.drain()
    pipeline_ms = (time.perf_counter() - began) * 1000
    with browser.lab.owner() as s:
        bill_count = s.execute(
            "SELECT count(DISTINCT bill_digest) AS n FROM inventory.container_software c "
            "JOIN inventory.server_current_snapshots snap ON snap.snapshot_id=c.snapshot_id "
            "WHERE snap.server_id=%s",
            (response.json()["server_id"],),
        ).fetchone()["n"]
        queue = s.execute(
            "SELECT coalesce(max(extract(epoch FROM clock_timestamp()-created_at)),0) AS seconds "
            "FROM automation.jobs WHERE status IN ('pending','queued','running','retry_pending')"
        ).fetchone()["seconds"]
    assert bill_count == 1
    assert pipeline_ms < 60000
    lock_ms = [
        record.wait_seconds * 1000 for record in caplog.records if hasattr(record, "wait_seconds")
    ]
    # A real 1,001-server manual report must fail before loading findings or rendering SMTP.
    from cve_common.database.engine import Database
    from cve_common.database.transactions import transaction
    from cve_notification.contracts import Preferences
    from cve_notification.reports import content

    notification, report, correlation = uuid4(), uuid4(), uuid4()
    prefix = "report-budget-" + uuid4().hex
    owner = browser.lab.bootstrap_id
    with browser.lab.owner() as session:
        session.execute(
            "INSERT INTO inventory.servers(display_name,inventory_hostname,inventory_name) "
            "SELECT %s||i,%s||i,%s||i FROM generate_series(1,1001) i",
            (prefix, prefix, prefix),
        )
        session.execute(
            "INSERT INTO automation.notification_intents(id,recipient_user_id,rule_id,template_id,"
            "kind,status,reason,correlation_id) SELECT %s,%s,r.id,t.id,'digest','ready',"
            "'review-fixture',%s FROM automation.notification_rules r CROSS JOIN "
            "automation.notification_templates t LIMIT 1",
            (notification, owner, correlation),
        )
        session.execute(
            "INSERT INTO automation.mail_reports(id,user_id,origin,correlation_id,state,"
            "notification_id) "
            "VALUES(%s,%s,'manual',%s,'ready',%s)",
            (report, owner, correlation, notification),
        )
        session.execute(
            "INSERT INTO automation.notification_history(notification_id,version,old_status,"
            "new_status,reason,correlation_id) VALUES(%s,1,NULL,'ready','review-fixture',%s)",
            (notification, correlation),
        )
        session.execute(
            "INSERT INTO automation.mail_report_servers(report_id,server_id) "
            "SELECT %s,id FROM inventory.servers WHERE display_name LIKE %s",
            (report, prefix + "%"),
        )
    database = Database(browser.lab.database("notification"))
    database.open()
    try:
        began = time.perf_counter()
        async with transaction(database) as session:
            rendered = await content(session, notification, owner, Preferences())
        report_limit_ms = (time.perf_counter() - began) * 1000
        assert rendered == ([], "report_size_limit", False)
        assert report_limit_ms < 5000
    finally:
        await database.close()
    result = {
        "checked_at": datetime.now(UTC).isoformat(),
        "source": source,
        "source_unchanged": source == identity(root),
        "hardware": {"platform": platform.platform(), "cpu_count": os.cpu_count()},
        "configuration": {
            "tabs": 3,
            "requests": 30,
            "containers": 20,
            "packages_per_bill": 500,
            "argon_memory": browser.service.settings.argon_memory,
            "argon_concurrency": browser.service.settings.argon_concurrency,
        },
        "reads": distribution(latencies),
        "error_rate": sum(s != 200 for s in statuses) / len(statuses),
        "vault_with_reads_ms": vault_with_reads_ms,
        "container_pipeline_ms": pipeline_ms,
        "report_servers": 1001,
        "report_limit_ms": report_limit_ms,
        "distinct_bills": bill_count,
        "lock_wait": distribution(lock_ms),
        "queue_oldest_seconds": float(queue),
        "python_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "child_peak_rss_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
        "scope": "isolated local synthetic laboratory; no production SLO claim",
    }
    path = root / ".runtime/test-reports/review-contention.json"
    path.write_text(json.dumps(result, indent=2) + "\n")
    path.chmod(0o600)
