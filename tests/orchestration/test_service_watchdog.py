"""The real scheduled n8n workflow recovers even its usual HTTP control endpoints."""

import asyncio
import contextlib
import json
import time
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

from scripts.automation_executor.agent import process_restart
from scripts.automation_executor.watchdog import observe
from scripts.database import manage as db
from scripts.infrastructure.manage import Config, compose, docker_command, run
from tests.authorization.integration.conftest import actor
from tests.database.helpers import required_row
from tests.inventory_upload.integration.conftest import Browser
from tests.orchestration.test_runtime import browser, eventually, platform, upload_lab

__all__ = ["browser", "platform", "upload_lab"]
pytestmark = pytest.mark.orchestration


def snapshot(config: Config, group: str) -> dict[str, Any]:
    container = json.loads(
        run([*docker_command(), "inspect", config.project + "-" + group + "-1"]).stdout
    )[0]
    children = json.loads(
        run(
            [*docker_command(), "exec", container["Id"], "cat", "/tmp/cve-application-state.json"]
        ).stdout
    )["children"]
    return {"id": container["Id"], "started": container["State"]["StartedAt"], "children": children}


def signal_child(container: str, pid: int, signal: str) -> None:
    run(
        [
            *docker_command(),
            "exec",
            container,
            "python",
            "-c",
            f"import os,signal\ntry:os.kill({pid},signal.{signal})\nexcept ProcessLookupError:pass",
        ]
    )


async def test_scheduled_watchdog_recovers_api_and_notification_without_restarting_containers(
    platform: Config,
) -> None:
    await asyncio.to_thread(
        eventually,
        platform,
        "SELECT checked_at>clock_timestamp()-interval '45 seconds' AS ready "
        "FROM status.watchdog_runs",
    )
    await asyncio.to_thread(observe, platform)
    before = {g: snapshot(platform, g) for g in ("cve-api", "cve-processing")}
    targets = {"cve-api": "cve-api", "cve-processing": "cve-notification"}
    for group, role in targets.items():
        signal_child(before[group]["id"], before[group]["children"][role], "SIGSTOP")
    started = time.monotonic()
    workers: list[asyncio.Task[None]] = []

    async def observations() -> None:
        while True:
            await asyncio.to_thread(observe, platform)
            await asyncio.sleep(30)

    async def executor() -> None:
        while True:
            await asyncio.to_thread(process_restart, platform)
            await asyncio.sleep(1)

    try:
        workers = [
            asyncio.create_task(observations()),
            asyncio.create_task(executor()),
            asyncio.create_task(executor()),
        ]
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT count(*)=2 AND bool_and(state='succeeded') AS ready "
            "FROM status.service_restarts WHERE origin='watchdog' "
            "AND service_id IN ('api','notification')",
            (),
            180,
        )
    finally:
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        for group, role in targets.items():
            with contextlib.suppress(Exception):
                signal_child(before[group]["id"], before[group]["children"][role], "SIGCONT")
    after = {g: snapshot(platform, g) for g in targets}
    for group, role in targets.items():
        assert before[group]["id"] == after[group]["id"]
        assert before[group]["started"] == after[group]["started"]
        assert before[group]["children"][role] != after[group]["children"][role]
        assert all(
            pid == after[group]["children"][peer]
            for peer, pid in before[group]["children"].items()
            if peer != role
        )
    with db.connect(platform) as s:
        requests = s.execute(
            "SELECT r.service_id,r.state,r.actor_id,r.origin,q.workflow_id,q.execution_id "
            "FROM status.service_restarts r JOIN automation.n8n_queue q ON q.id=r.queue_id "
            "WHERE r.origin='watchdog' ORDER BY r.service_id"
        ).fetchall()
        assert len(requests) == 2
        assert all(
            r["workflow_id"] == "cve-control-watchdog" and r["actor_id"] is None for r in requests
        )
    with db.connect(platform, database="n8n") as s:
        assert (
            required_row(
                s.execute(
                    "SELECT count(*) AS n FROM execution_entity "
                    "WHERE \"workflowId\"='cve-control-watchdog' "
                    "AND status='success'"
                )
            )["n"]
            >= 3
        )
    report = {
        "scheduled_n8n_authorization": True,
        "api_and_notification_recovered": True,
        "containers_unchanged": True,
        "peer_processes_unchanged": True,
        "checked_at": time.time(),
        "recovery_seconds": round(time.monotonic() - started, 2),
    }
    (platform.root / ".runtime/test-reports/service-watchdog.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )


async def test_status_cache_stays_fresh_when_database_diagnostics_time_out(
    platform: Config,
    browser: Browser,
) -> None:
    from scripts.notifications import manage as notifications
    from scripts.services import manage as api

    active = replace(platform, values={**platform.values, "STATUS_COLLECTOR_PAUSED": "false"})
    api.prepare(active)
    compose(
        active,
        ["up", "-d", "--no-deps", "--wait", "--wait-timeout", "60", "cve-api"],
        managed=False,
    )
    notifications.guard(active)
    person = await actor(browser)
    item = json.loads(run([*docker_command(), "inspect", platform.project + "-cve-api-1"]).stdout)[
        0
    ]
    address = item["NetworkSettings"]["Networks"][platform.project + "_cve_internal"]["IPAddress"]
    await asyncio.to_thread(
        eventually,
        platform,
        "SELECT count(*)>0 AS ready FROM automation.jobs "
        "WHERE job_type='status.collect' AND status='succeeded'",
    )
    with db.connect(platform) as s:
        old_definition = required_row(
            s.execute("SELECT pg_get_functiondef('status.sample()'::regprocedure) AS d")
        )["d"]
        count = required_row(s.execute("SELECT count(*) n FROM status.check_observations"))["n"]
        s.execute(
            "CREATE OR REPLACE FUNCTION status.sample() RETURNS jsonb LANGUAGE plpgsql "
            "SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN "
            "PERFORM pg_sleep(3); RETURN '{}'::jsonb; END $$"
        )
        cutoff = required_row(s.execute("SELECT clock_timestamp() AS t"))["t"]
    try:
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT count(*)>0 AS ready FROM automation.jobs WHERE job_type='status.collect' "
            "AND status='succeeded' AND created_at>%s",
            (cutoff,),
            90,
        )
        async with httpx.AsyncClient(trust_env=False, timeout=5) as client:
            result = await client.get(
                f"http://{address}:8000/api/v1/status/overview",
                headers={
                    "host": urlsplit(browser.service.settings.origin).netloc,
                    "x-cve-auth-gateway": browser.service.gateway,
                    "x-cve-auth-scheme": "https",
                    "x-real-ip": "192.0.2.18",
                    "cookie": "__Host-cve-session=" + person.cookie,
                },
            )
        assert result.status_code == 200, result.text
        service = next(v for v in result.json()["services"] if v["id"] == "api")
        assert service["state"] == "healthy" and not service["stale"]
        with db.connect(platform) as s:
            assert (
                required_row(s.execute("SELECT count(*) n FROM status.check_observations"))["n"]
                == count
            )
    finally:
        with db.connect(platform) as s:
            s.execute(old_definition)
