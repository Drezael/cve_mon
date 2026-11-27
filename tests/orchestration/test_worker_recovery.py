"""Real n8n recovery preserves Git checkpoints; independent restarts keep peers alive."""

import asyncio
import json
import time
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import pytest
from cve_common.jobs.errors import ErrorCode, JobError
from cve_common.jobs.models import Job
from cve_importer.adapters import Adapters, Page

from scripts.automation_executor.agent import process_restart
from scripts.database import manage as db
from scripts.infrastructure.manage import Config, docker_command, run
from tests.authorization.integration.conftest import actor
from tests.cve_importer.conftest import Lab as SourceLab
from tests.cve_importer.test_git_source import configure, upstream, write
from tests.cve_importer.test_pipeline import Harness
from tests.database.helpers import required_row
from tests.inventory_upload.integration.conftest import Browser
from tests.orchestration.test_runtime import browser, eventually, platform, upload_lab

__all__ = ["browser", "platform", "upload_lab", "upstream"]
pytestmark = pytest.mark.orchestration


async def test_n8n_boot_recovery_resumes_the_same_git_checkpoint(
    platform: Config,
    tmp_path: Path,
    upstream: tuple[Path, Callable[[], str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(SourceLab(platform), tmp_path / "recover")
    configure(harness)
    root, publish = upstream
    for number in (99101, 99102, 99103):
        write(root, f"CVE-2096-{number}")
    pinned = publish()
    original = Adapters.next
    calls = 0

    async def interrupted(self: Adapters, progress: dict[str, object]) -> Page:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise JobError(ErrorCode.NETWORK, diagnostic_code="GIT_COMMAND_FAILED")
        return await original(self, progress)

    try:
        monkeypatch.setattr(Adapters, "next", interrupted)
        identity = harness.schedule("cve_list")
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT j.status='queued' AS ready FROM cve.import_runs r "
            "JOIN automation.jobs j ON j.id=r.job_id WHERE r.id=%s",
            (identity,),
        )
        with pytest.raises(JobError):
            await harness.execute()
        before = harness.row(identity)
        assert before["progress"]["git"]["offset"] == before["read_count"] == 2
        with db.connect(platform) as s:
            old = required_row(
                s.execute("SELECT * FROM automation.jobs WHERE id=%s", (before["job_id"],))
            )
            assert old
        await harness.repository.finish(
            Job.model_validate(old),
            "failed",
            ErrorCode.NETWORK,
            diagnostic_code="GIT_COMMAND_FAILED",
            error_class="JobError",
        )
        assert harness.row(identity)["status"] == "failed"
        boot = uuid4()
        await harness.repository.request_recovery(boot)
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT j.status='queued' AS ready FROM cve.import_runs r "
            "JOIN automation.jobs j ON j.id=r.job_id WHERE r.id=%s AND r.job_id<>%s",
            (identity, before["job_id"]),
        )
        # Repeating one boot request cannot create another replay.
        await harness.repository.request_recovery(boot)
        current = harness.row(identity)
        assert current["progress"] == before["progress"] and current["read_count"] == 2
        monkeypatch.setattr(Adapters, "next", original)
        await harness.execute()
        completed = harness.row(identity)
        assert completed["effective_status"] == "completed" and completed["read_count"] == 3
        with db.connect(platform) as s:
            assert (
                required_row(
                    s.execute(
                        "SELECT count(*) AS n FROM automation.jobs WHERE replay_of=%s",
                        (before["job_id"],),
                    )
                )["n"]
                == 1
            )
            prior = required_row(
                s.execute(
                    "SELECT status,diagnostic_code FROM automation.jobs WHERE id=%s",
                    (before["job_id"],),
                )
            )
            assert prior == {"status": "failed", "diagnostic_code": "GIT_COMMAND_FAILED"}
            assert not required_row(
                s.execute(
                    "SELECT automation.job_failure_unresolved(%s) AS unresolved",
                    (before["job_id"],),
                )
            )["unresolved"]
            cursor = required_row(
                s.execute(
                    "SELECT cursor FROM cve.source_streams "
                    "WHERE source_id='cve_list' AND stream='main'"
                )
            )["cursor"]
            assert cursor["git_commit"] == pinned
    finally:
        await harness.transport.close()
        await harness.database.close()


async def test_n8n_process_restarts_do_not_wait_for_another_service(
    platform: Config, browser: Browser
) -> None:
    admin = await actor(browser)
    headers = {"cookie": "__Host-cve-session=" + admin.cookie, "x-csrf-token": admin.csrf}
    item = json.loads(
        run([*docker_command(), "inspect", platform.project + "-cve-processing-1"]).stdout
    )[0]
    container = item["Id"]
    state_command = [*docker_command(), "exec", container, "cat", "/tmp/cve-application-state.json"]
    before = json.loads(run(state_command).stdout)["children"]
    old = before["cve-enricher"]
    run(
        [
            *docker_command(),
            "exec",
            container,
            "python",
            "-c",
            f"import os,signal;os.kill({old},signal.SIGSTOP)",
        ]
    )
    first = None
    try:
        requested = []
        for service in ("enricher", "inventory"):
            response = await browser.client.post(
                "/api/v1/status/services/" + service + "/restart",
                headers={**headers, "Idempotency-Key": str(uuid4())},
                json={"reason": "Independent process recovery test"},
            )
            assert response.status_code == 202, response.text
            requested.append(response.json()["id"])
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT count(*)=2 AND bool_and(q.finished_at<clock_timestamp()-interval '2 seconds') "
            "AS ready FROM status.service_restarts r JOIN automation.n8n_queue q "
            "ON q.id=r.queue_id "
            "WHERE r.id=ANY(%s::uuid[]) AND r.state='authorized'",
            (requested,),
        )
        first = asyncio.create_task(asyncio.to_thread(process_restart, platform))
        await asyncio.sleep(0.5)
        started = time.monotonic()
        await asyncio.wait_for(asyncio.to_thread(process_restart, platform), 12)
        assert time.monotonic() - started < 12 and not first.done()
        middle = json.loads(run(state_command).stdout)["children"]
        assert middle["cve-inventory"] != before["cve-inventory"]
        run(
            [
                *docker_command(),
                "exec",
                container,
                "python",
                "-c",
                "import urllib.request;assert urllib.request.urlopen('http://127.0.0.1:8002/health/ready').status==200",
            ]
        )
    finally:
        # The stopped process can now receive its pending TERM and finish draining.
        run(
            [
                *docker_command(),
                "exec",
                container,
                "python",
                "-c",
                f"import os,signal\ntry:os.kill({old},signal.SIGCONT)\n"
                "except ProcessLookupError:pass",
            ]
        )
        if first is not None:
            await asyncio.wait_for(first, 45)
    after = json.loads(run(state_command).stdout)["children"]
    assert after["cve-enricher"] != before["cve-enricher"]
    assert all(
        after[role] == pid
        for role, pid in before.items()
        if role not in {"cve-enricher", "cve-inventory"}
    )
    current = json.loads(run([*docker_command(), "inspect", container]).stdout)[0]
    assert current["State"]["StartedAt"] == item["State"]["StartedAt"]
    report = {
        "n8n_authorized": True,
        "different_services_restart_concurrently": True,
        "unresponsive_service_does_not_block_peer": True,
        "container_unchanged": True,
        "unrelated_processes_unchanged": True,
    }
    (platform.root / ".runtime/test-reports/worker-recovery.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )


async def test_n8n_periodic_recovery_resumes_network_failure_without_restart(
    platform: Config,
    tmp_path: Path,
    upstream: tuple[Path, Callable[[], str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with db.connect(platform) as session:
        restart_count = required_row(
            session.execute("SELECT count(*) n FROM status.service_restarts")
        )["n"]
    harness = Harness(SourceLab(platform), tmp_path / "recover")
    configure(harness)
    root, publish = upstream
    for number in (99101, 99102, 99103):
        write(root, f"CVE-2096-{number}")
    pinned = publish()
    original = Adapters.next
    calls = 0

    async def interrupted(self: Adapters, progress: dict[str, object]) -> Page:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise JobError(ErrorCode.NETWORK, diagnostic_code="GIT_COMMAND_FAILED")
        return await original(self, progress)

    try:
        monkeypatch.setattr(Adapters, "next", interrupted)
        identity = harness.schedule("cve_list")
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT j.status='queued' AS ready FROM cve.import_runs r "
            "JOIN automation.jobs j ON j.id=r.job_id WHERE r.id=%s",
            (identity,),
        )
        with pytest.raises(JobError):
            await harness.execute()
        before = harness.row(identity)
        assert before["progress"]["git"]["offset"] == before["read_count"] == 2
        with db.connect(platform) as s:
            old = required_row(
                s.execute("SELECT * FROM automation.jobs WHERE id=%s", (before["job_id"],))
            )
            assert old
        await harness.repository.finish(
            Job.model_validate(old),
            "failed",
            ErrorCode.NETWORK,
            diagnostic_code="GIT_COMMAND_FAILED",
            error_class="JobError",
        )
        assert harness.row(identity)["status"] == "failed"
        with db.connect(platform, "cve_migrator") as session:
            session.execute("SET ROLE postgres_owner")
            session.execute(
                "UPDATE automation.jobs SET created_at=clock_timestamp()-interval '2 minutes',"
                "finished_at=clock_timestamp()-interval '70 seconds' WHERE id=%s",
                (old["id"],),
            )
            session.execute(
                "UPDATE automation.workflow_settings SET auto_updates=true,"
                "next_update_at=clock_timestamp()+interval '1 day'"
            )
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT j.status='queued' AS ready FROM cve.import_runs r "
            "JOIN automation.jobs j ON j.id=r.job_id WHERE r.id=%s AND r.job_id<>%s",
            (identity, before["job_id"]),
        )
        # No boot request or service restart: the regular n8n import tick must recover it.
        current = harness.row(identity)
        assert current["progress"] == before["progress"] and current["read_count"] == 2
        monkeypatch.setattr(Adapters, "next", original)
        await harness.execute()
        completed = harness.row(identity)
        assert completed["effective_status"] == "completed" and completed["read_count"] == 3
        with db.connect(platform) as s:
            assert (
                required_row(
                    s.execute(
                        "SELECT count(*) AS n FROM automation.jobs WHERE replay_of=%s",
                        (before["job_id"],),
                    )
                )["n"]
                == 1
            )
            prior = required_row(
                s.execute(
                    "SELECT status,diagnostic_code FROM automation.jobs WHERE id=%s",
                    (before["job_id"],),
                )
            )
            assert prior == {"status": "failed", "diagnostic_code": "GIT_COMMAND_FAILED"}
            assert not required_row(
                s.execute(
                    "SELECT automation.job_failure_unresolved(%s) AS unresolved",
                    (before["job_id"],),
                )
            )["unresolved"]
            cursor = required_row(
                s.execute(
                    "SELECT cursor FROM cve.source_streams "
                    "WHERE source_id='cve_list' AND stream='main'"
                )
            )["cursor"]
            assert cursor["git_commit"] == pinned
        with db.connect(platform) as session:
            receipt = required_row(
                session.execute(
                    "SELECT count(*) AS n FROM automation.import_recovery_receipts "
                    "WHERE failed_job_id=%s",
                    (old["id"],),
                )
            )
            assert receipt["n"] == 1
            assert (
                required_row(session.execute("SELECT count(*) AS n FROM status.service_restarts"))[
                    "n"
                ]
                == restart_count
            )
    finally:
        with db.connect(platform) as session:
            session.execute("UPDATE automation.workflow_settings SET auto_updates=false")
        await harness.transport.close()
        await harness.database.close()
