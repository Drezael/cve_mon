"""n8n periodically resumes an interrupted Git checkpoint without a process restart."""

from collections.abc import Callable
from pathlib import Path

import psycopg
import pytest
from cve_common.jobs.errors import ErrorCode, JobError
from cve_common.jobs.models import Job
from cve_importer.adapters import Adapters, Page

from scripts.database import manage as db
from tests.cve_importer.test_git_source import configure, git_harness, upstream, write
from tests.cve_importer.test_pipeline import Harness
from tests.database.helpers import required_row

__all__ = ["git_harness", "upstream"]
pytestmark = pytest.mark.cve_importer


def tick(harness: Harness) -> dict[str, object]:
    with db.connect(harness.lab.config, "workflow_control") as s:
        value = required_row(
            s.execute(
                "SELECT automation.workflow_tick('import','transient-test',"
                "'cve-control-import') AS v"
            )
        )["v"]
        assert isinstance(value, dict)
        return value


def release(harness: Harness) -> None:
    with db.connect(harness.lab.config, "workflow_control") as s:
        for _ in range(100):
            item = required_row(
                s.execute(
                    "SELECT automation.n8n_claim('recovery-consumer','cve-control-queue') AS v"
                )
            )["v"]
            if item["kind"] == "empty":
                return
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,%s,%s)",
                (
                    item["id"],
                    item["lease_token"],
                    item["kind"],
                    "recovery-consumer",
                    "cve-control-queue",
                ),
            )
    raise AssertionError("Recovery queue did not drain")


async def test_periodic_recovery_preserves_checkpoint_and_respects_backoff_and_disable(
    git_harness: Harness,
    upstream: tuple[Path, Callable[[], str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h = git_harness
    configure(h)
    root, publish = upstream
    for number in (89101, 89102, 89103):
        write(root, f"CVE-2097-{number}")
    pinned = publish()
    original = Adapters.next
    calls = 0

    async def interrupted(self: Adapters, progress: dict[str, object]) -> Page:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise JobError(ErrorCode.NETWORK, diagnostic_code="GIT_CONNECTION_RESET")
        return await original(self, progress)

    monkeypatch.setattr(Adapters, "next", interrupted)
    identity = h.schedule("cve_list")
    with pytest.raises(JobError):
        await h.execute()
    before = h.row(identity)
    with h.lab.owner() as s:
        old = Job.model_validate(
            required_row(
                s.execute("SELECT * FROM automation.jobs WHERE id=%s", (before["job_id"],))
            )
        )
    await h.repository.finish(
        old, "failed", ErrorCode.NETWORK, diagnostic_code="GIT_CONNECTION_RESET"
    )
    assert before["read_count"] == before["progress"]["git"]["offset"] == 2
    with h.lab.owner() as s:
        s.execute(
            "UPDATE automation.workflow_settings SET enabled=true,auto_updates=false,"
            "next_update_at=clock_timestamp()+interval '1 day'"
        )
    assert tick(h)["recovered"] == 0
    with h.lab.owner() as s:
        s.execute("UPDATE automation.workflow_settings SET auto_updates=true")
    assert tick(h)["recovered"] == 0  # A network flap does not cause a tight retry loop.
    with h.lab.owner() as s:
        s.execute(
            "UPDATE automation.jobs SET created_at=clock_timestamp()-interval '2 minutes',"
            "finished_at=clock_timestamp()-interval '70 seconds' WHERE id=%s",
            (old.id,),
        )
    try:
        assert tick(h)["recovered"] == 1
        assert tick(h)["recovered"] == 0
        current = h.row(identity)
        assert current["job_id"] != old.id and current["progress"] == before["progress"]
        release(h)
        monkeypatch.setattr(Adapters, "next", original)
        await h.execute()
        done = h.row(identity)
        assert done["effective_status"] == "completed" and done["read_count"] == 3
        assert done["progress"]["git"]["head"] == pinned
        with h.lab.owner() as s:
            assert (
                required_row(
                    s.execute("SELECT status FROM automation.jobs WHERE id=%s", (old.id,))
                )["status"]
                == "failed"
            )
            assert not required_row(
                s.execute("SELECT automation.job_failure_unresolved(%s) AS v", (old.id,))
            )["v"]
            assert (
                required_row(
                    s.execute(
                        "SELECT count(*) AS n FROM automation.import_recovery_receipts "
                        "WHERE failed_job_id=%s",
                        (old.id,),
                    )
                )["n"]
                == 1
            )
    finally:
        with h.lab.owner() as s:
            s.execute("UPDATE automation.workflow_settings SET enabled=false,auto_updates=false")
    with (
        db.connect(h.lab.config, "importer") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("SELECT automation.workflow_tick('import','forged','cve-control-import')")
