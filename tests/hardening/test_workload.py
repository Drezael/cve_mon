"""Scaled actual acceptance, worker pipelines, scoped reads and finite local resource budgets."""

import asyncio
import json
import os
import resource
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from scripts.hardening.metrics import distribution
from scripts.infrastructure.manage import compose, docker_command, run
from tests.authorization.integration.conftest import actor, call
from tests.findings.test_native import Harness
from tests.inventory_processor.test_normalization import sample
from tests.inventory_processor.test_processing import drain
from tests.inventory_upload.integration.conftest import provision, technical

pytestmark = pytest.mark.hardening


async def test_scaled_native_workload(harness: Harness) -> None:
    browser = harness.browser
    assert browser.lab.config.project.startswith("cve-db-test-")
    stage = os.environ.get("HARDENING_STAGE", "after")
    assert stage in {"before", "after"}
    report: dict[str, Any] = {"stage": stage, "synthetic": True, "levels": []}
    admin = await actor(browser)
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
        Path(".runtime/test-reports/phase-23-query-failure.json").write_text(
            json.dumps(query_errors[:20])
        )

    assert browser.service.database.engine is not None
    event.listen(browser.service.database.engine.sync_engine, "handle_error", error_seen)
    upload = await provision(browser)
    started_cpu = time.process_time()
    for servers, packages in [(100, 100), (1000, 1000), (10000, 10000)]:
        prefix = "load-" + uuid4().hex
        with browser.lab.owner() as c:
            c.execute(
                "INSERT INTO inventory.servers(display_name,inventory_hostname,inventory_name) "
                "SELECT %s||i,%s||i,%s||i FROM generate_series(1,%s) i",
                (prefix, prefix, prefix, servers),
            )
            c.execute("ANALYZE inventory.servers")
        value = sample()
        value["server_id"] = upload.server["id"]
        base = value["packages"]["items"][0]
        value["packages"]["items"] = [
            {**base, "name": "load-package-" + str(i)} for i in range(packages)
        ]
        value["packages"]["items"][0] = {
            **base,
            "source_package": {"name": "apache2", "version": base["version"]},
        }
        body = json.dumps(value).encode()
        began = time.monotonic()
        accepted = await technical(browser, upload, body)
        upload_ms = (time.monotonic() - began) * 1000
        assert accepted.status_code == 202, accepted.text
        began = time.monotonic()
        await drain(browser, concurrency=2)
        processing_ms = (time.monotonic() - began) * 1000
        with browser.lab.owner() as c:
            row = c.execute(
                "SELECT snapshot_id,status FROM inventory.processing_status WHERE submission_id=%s",
                (accepted.json()["submission_id"],),
            ).fetchone()
            assert row["status"] == "completed"
            count = c.execute(
                "SELECT count(*) AS n FROM inventory.packages WHERE snapshot_id=%s",
                (row["snapshot_id"],),
            ).fetchone()["n"]
            assert count == packages
        identity, revision = harness.matcher.seed()
        began = time.monotonic()
        await harness.matcher.drain()
        harness.matcher.enqueue("evaluate_vulnerability", enrichment_revision_id=revision)
        await harness.matcher.drain()
        matching_ms = (time.monotonic() - began) * 1000
        began = time.monotonic()
        await harness.drain()
        finding_ms = (time.monotonic() - began) * 1000
        with browser.lab.owner() as c:
            assert c.execute(
                "SELECT 1 FROM findings.current_findings WHERE server_id=%s AND cve_id=%s",
                (upload.server["id"], identity),
            ).fetchone()
            plan = c.execute(
                "EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) SELECT id FROM inventory.servers "
                "WHERE status<>'archived' ORDER BY id LIMIT 25"
            ).fetchone()["QUERY PLAN"]
            connections = c.execute("SELECT count(*) AS n FROM pg_stat_activity").fetchone()["n"]
            queues = c.execute(
                "SELECT status,count(*) AS n FROM automation.jobs GROUP BY status"
            ).fetchall()
            if stage == "after":
                c.execute("SET LOCAL jit=off")
                statement = (
                    "WITH page AS MATERIALIZED (SELECT s.id FROM dashboard.server_list_index s "
                    "WHERE s.status='active' ORDER BY s.display_order,s.id LIMIT 25) "
                    "SELECT s.* FROM page CROSS JOIN LATERAL "
                    "(SELECT detail.* FROM dashboard.server_security detail "
                    "WHERE detail.id=page.id OFFSET 0) s ORDER BY s.display_order,s.id"
                )
            else:
                statement = (
                    "SELECT s.* FROM dashboard.server_security s "
                    "WHERE s.status='active' ORDER BY s.display_order,s.id LIMIT 25"
                )
            full_plan = c.execute("EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) " + statement).fetchone()[
                "QUERY PLAN"
            ]
        semaphore = asyncio.Semaphore(4)
        latencies: list[float] = []
        statuses: list[int] = []

        async def read(
            number: int,
            gate: asyncio.Semaphore = semaphore,
            timings: list[float] = latencies,
            outcomes: list[int] = statuses,
        ) -> None:
            async with gate:
                began = time.monotonic()
                response = await call(
                    browser,
                    admin,
                    "GET",
                    "security/servers?limit=25&offset=" + str((number % 4) * 25),
                )
                timings.append((time.monotonic() - began) * 1000)
                if stage == "after":
                    assert response.status_code == 200, response.text
                if response.status_code == 200:
                    assert len(response.json()["items"]) <= 25
                outcomes.append(response.status_code)
                assert len(response.content) < 262144

        await asyncio.gather(*(read(i) for i in range(24)))
        assert max(latencies) < 15000
        assert upload_ms < 15000 and processing_ms < 30000
        assert matching_ms < 60000 and finding_ms < 30000
        ident = compose(browser.lab.config, ["ps", "-q", "cve-postgres"]).stdout.strip()
        stats = json.loads(
            run([*docker_command(), "stats", "--no-stream", "--format", "{{json .}}", ident]).stdout
        )
        report["levels"].append(
            {
                "added_servers": servers,
                "packages": packages,
                "body_bytes": len(body),
                "upload_ms": upload_ms,
                "processing_ms": processing_ms,
                "matching_ms": matching_ms,
                "findings_ms": finding_ms,
                "api": distribution(latencies),
                "api_errors": sum(s != 200 for s in statuses),
                "api_statuses": statuses,
                "connections": connections,
                "queue": [dict(r) for r in queues],
                "postgres_stats": {k: stats[k] for k in ["CPUPerc", "MemUsage", "BlockIO", "PIDs"]},
                "query_plan": plan,
                "dashboard_plan": full_plan,
                "snapshot_packages_verified": count,
            }
        )
        Path(".runtime/test-reports/phase-23-performance-" + stage + ".json").write_text(
            json.dumps(report, indent=2, default=str)
        )
    report["python_cpu_seconds"] = time.process_time() - started_cpu
    report["python_peak_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report["child_peak_rss_kib"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    path = Path(".runtime/test-reports/phase-23-performance-" + stage + ".json")
    path.write_text(json.dumps(report, indent=2, default=str))
    path.chmod(0o600)
