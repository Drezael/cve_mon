"""Real shallow clone/pull/diff with a local upstream; no live CVE rows or network fixtures."""

import asyncio
import json
import subprocess
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cve_importer.git_source import GitSource
from sqlalchemy import text as sql_text

from tests.cve_importer.conftest import Lab
from tests.cve_importer.fixtures import cve
from tests.cve_importer.test_pipeline import Harness
from tests.database.helpers import required_row

pytestmark = pytest.mark.cve_importer


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
async def git_harness(import_lab: Lab, tmp_path: Path) -> AsyncIterator[Harness]:
    value = Harness(import_lab, tmp_path / "importer")
    try:
        yield value
    finally:
        await value.transport.close()
        await value.database.close()


@pytest.fixture
def upstream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Callable[[], str]]:
    remote, writer = tmp_path / "remote.git", tmp_path / "writer"
    remote.mkdir()
    git(remote, "init", "--bare", "--initial-branch=main")
    subprocess.run(["git", "clone", str(remote), str(writer)], check=True, capture_output=True)
    git(writer, "config", "user.name", "Synthetic fixture")
    git(writer, "config", "user.email", "fixture@example.test")
    # Production has a fixed HTTPS origin and disables file/SSH; only this fixture relaxes file.
    monkeypatch.setattr("cve_importer.git_source.REMOTE", remote.as_uri())
    prefix, environment = GitSource.prefix, GitSource.environment
    monkeypatch.setattr(
        GitSource, "prefix", lambda self: prefix(self) + ["-c", "protocol.file.allow=always"]
    )
    monkeypatch.setattr(
        GitSource, "environment", lambda self: {**environment(self), "GIT_ALLOW_PROTOCOL": "file"}
    )

    def publish() -> str:
        git(writer, "add", ".")
        git(writer, "commit", "-m", "Synthetic upstream change")
        git(writer, "push", "origin", "main")
        return git(writer, "rev-parse", "HEAD")

    return writer, publish


def write(root: Path, identity: str, *, text: str = "Example") -> Path:
    _, year, number = identity.split("-")
    path = root / "cves" / year / (str(int(number) // 1000) + "xxx") / (identity + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    value = cve(identifier=identity)
    value["containers"]["cna"]["descriptions"][0]["value"] = text
    path.write_text(json.dumps(value))
    return path


def configure(harness: Harness) -> None:
    harness.configuration = harness.configuration.model_copy(
        update={"enabled": ["cve_list"], "cve_list_transport": "git", "enrichment_batch_size": 2}
    )
    harness.service.configuration = harness.configuration
    harness.transport.configuration = harness.configuration


async def test_git_initial_pull_diff_noop_and_removed_records(
    git_harness: Harness, upstream: tuple[Path, Callable[[], str]]
) -> None:
    harness = git_harness
    root, publish = upstream
    configure(harness)
    for number in (81001, 81002, 81003):
        write(root, f"CVE-2026-{number}")
    initial = publish()
    first = await harness.run("cve_list")
    assert first["read_count"] == 3 and first["new_count"] == 3
    with harness.lab.owner() as connection:
        cursor = required_row(
            connection.execute(
                "SELECT cursor FROM cve.source_streams WHERE source_id='cve_list' AND stream='main'"
            )
        )
        assert cursor["cursor"]["git_commit"] == initial
        jobs = connection.execute(
            "SELECT payload FROM automation.jobs WHERE job_type='matching.index_v5_batch'"
        ).fetchall()
        assert sum(len(job["payload"]["revisions"]) for job in jobs) == 3
        assert not connection.execute(
            "SELECT 1 FROM automation.jobs WHERE job_type='cve.enrich.reconcile'"
        ).fetchone()
    write(root, "CVE-2026-81001", text="Changed")
    write(root, "CVE-2026-81004")
    (root / "cves/2026/81xxx/CVE-2026-81003.json").unlink()
    updated = publish()
    changed = await harness.run("cve_list", "incremental")
    assert changed["read_count"] == 3 and changed["new_count"] == 1
    assert changed["changed_count"] == 2 and changed["unchanged_count"] == 0
    with harness.lab.owner() as connection:
        assert not required_row(
            connection.execute(
                "SELECT present FROM cve.source_records WHERE source_id='cve_list' "
                "AND external_id='CVE-2026-81003'"
            )
        )["present"]
        assert (
            required_row(
                connection.execute(
                    "SELECT cursor FROM cve.source_streams "
                    "WHERE source_id='cve_list' AND stream='main'"
                )
            )["cursor"]["git_commit"]
            == updated
        )
        before = required_row(
            connection.execute(
                "SELECT count(*) n FROM automation.jobs WHERE job_type='matching.index_v5_batch'"
            )
        )["n"]
    unchanged = await harness.run("cve_list", "incremental")
    assert unchanged["read_count"] == 0
    with harness.lab.owner() as connection:
        assert (
            required_row(
                connection.execute(
                    "SELECT count(*) n FROM automation.jobs "
                    "WHERE job_type='matching.index_v5_batch'"
                )
            )["n"]
            == before
        )
    assert (
        git(harness.transport.scratch / "git/cvelistV5", "rev-parse", "--is-shallow-repository")
        == "true"
    )
    moved = root / "cves/2026/82xxx/CVE-2026-81004.json"
    moved.parent.mkdir(parents=True)
    (root / "cves/2026/81xxx/CVE-2026-81004.json").rename(moved)
    publish()
    renamed = await harness.run("cve_list", "incremental")
    assert renamed["read_count"] == renamed["unchanged_count"] == 1
    with harness.lab.owner() as connection:
        assert required_row(
            connection.execute(
                "SELECT present FROM cve.source_records WHERE source_id='cve_list' "
                "AND external_id='CVE-2026-81004'"
            )
        )["present"]


async def test_interrupted_git_page_resumes_pinned_commit_before_next_pull(
    git_harness: Harness, upstream: tuple[Path, Callable[[], str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from cve_common.jobs.errors import ErrorCode, JobError
    from cve_common.jobs.models import Job
    from cve_importer.adapters import Adapters, Page

    harness = git_harness
    configure(harness)
    root, publish = upstream
    for number in (82001, 82002, 82003):
        write(root, f"CVE-2026-{number}")
    pinned = publish()
    original = Adapters.next
    calls = 0

    async def interrupt(self: Adapters, progress: dict[str, Any]) -> Page:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise JobError(ErrorCode.TEMPORARY)
        return await original(self, progress)

    monkeypatch.setattr(Adapters, "next", interrupt)
    run = harness.schedule("cve_list")
    with pytest.raises(JobError):
        await harness.execute()
    with harness.lab.owner() as connection:
        state = required_row(
            connection.execute("SELECT * FROM cve.import_runs WHERE id=%s", (run,))
        )
        assert state["progress"]["git"]["offset"] == 2 and state["read_count"] == 2
        job = Job.model_validate(
            required_row(
                connection.execute("SELECT * FROM automation.jobs WHERE id=%s", (state["job_id"],))
            )
        )
    await harness.repository.finish(job, "retry", ErrorCode.TEMPORARY)
    with harness.lab.owner() as connection:
        connection.execute(
            "UPDATE automation.jobs SET scheduled_at=clock_timestamp() WHERE id=%s", (job.id,)
        )
    write(root, "CVE-2026-82001", text="Later upstream commit")
    later = publish()
    monkeypatch.setattr(Adapters, "next", original)
    await harness.execute()
    assert harness.row(run)["effective_status"] == "completed"
    assert harness.row(run)["read_count"] == 3
    with harness.lab.owner() as connection:
        cursor = required_row(
            connection.execute(
                "SELECT cursor FROM cve.source_streams WHERE source_id='cve_list' AND stream='main'"
            )
        )["cursor"]
        assert cursor["git_commit"] == pinned
    next_run = await harness.run("cve_list", "incremental")
    assert next_run["read_count"] == 1 and next_run["changed_count"] == 1
    with harness.lab.owner() as connection:
        assert (
            required_row(
                connection.execute(
                    "SELECT cursor FROM cve.source_streams "
                    "WHERE source_id='cve_list' AND stream='main'"
                )
            )["cursor"]["git_commit"]
            == later
        )


def test_reset_clears_cve_rows_and_preserves_configuration_in_rollback(import_lab: Lab) -> None:
    from scripts.cve_importer.reset import reset_in
    from scripts.database import manage as db

    with db.connect(import_lab.config) as connection:
        from tests.database.helpers import server, snapshot, user

        person = user(connection)
        target = server(connection)
        snap = snapshot(connection, target)
        report = required_row(
            connection.execute(
                "INSERT INTO automation.mail_reports(user_id,origin,correlation_id) "
                "VALUES(%s,'manual',%s) RETURNING *",
                (person, uuid4()),
            )
        )
        connection.execute(
            "INSERT INTO automation.mail_report_servers(report_id,server_id,snapshot_id) "
            "VALUES(%s,%s,%s)",
            (report["id"], target, snap),
        )
        before = required_row(connection.execute("SELECT count(*) n FROM security.roles"))["n"]
        result = reset_in(connection)
        assert not any(
            name.startswith(("security.", "inventory.")) for name in result["truncated_tables"]
        )
        assert "matching.inventory_keys" not in result["truncated_tables"]
        assert (
            required_row(connection.execute("SELECT count(*) n FROM cve.source_records"))["n"] == 0
        )
        assert (
            required_row(connection.execute("SELECT count(*) n FROM cve.enrichment_identities"))[
                "n"
            ]
            == 0
        )
        assert (
            required_row(
                connection.execute(
                    "SELECT count(*) n FROM automation.jobs WHERE job_type LIKE 'cve.%'"
                )
            )["n"]
            == 0
        )
        assert (
            required_row(connection.execute("SELECT count(*) n FROM security.roles"))["n"] == before
        )
        assert (
            required_row(connection.execute("SELECT count(*) n FROM cve.source_leases"))["n"] == 1
        )
        assert [
            r["id"] for r in connection.execute("SELECT id FROM cve.sources WHERE enabled")
        ] == ["cve_list"]
        assert (
            required_row(
                connection.execute(
                    "SELECT * FROM automation.mail_reports WHERE id=%s", (report["id"],)
                )
            )
            == report
        )
        assert (
            required_row(
                connection.execute(
                    "SELECT snapshot_id FROM automation.mail_report_servers WHERE report_id=%s",
                    (report["id"],),
                )
            )["snapshot_id"]
            == snap
        )
        connection.rollback()


async def test_complete_partial_scan_retries_only_failed_unchanged_files(
    git_harness: Harness, upstream: tuple[Path, Callable[[], str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from cve_importer.adapters import Page

    harness = git_harness
    configure(harness)
    root, publish = upstream
    write(root, "CVE-2026-83001")
    write(root, "CVE-2026-83002")
    commit = publish()
    original = GitSource.page

    async def older_validator(
        self: GitSource, progress: dict[str, Any], previous: dict[str, Any]
    ) -> Page:
        page = await original(self, progress, previous)
        invalid = [r for r in page.records if r["external_id"] == "CVE-2026-83002"]
        if invalid:
            page.records = [r for r in page.records if r["external_id"] != "CVE-2026-83002"]
            page.errors.append(
                {"position": invalid[0]["position"], "code": "invalid_source_schema"}
            )
        return page

    monkeypatch.setattr(GitSource, "page", older_validator)
    failed = harness.schedule("cve_list")
    await harness.execute()
    assert harness.row(failed)["effective_status"] == "partial"
    assert harness.row(failed)["read_count"] == 2
    monkeypatch.setattr(GitSource, "page", original)
    # There is no upstream diff. Only the previously unsuccessful path needs validation again.
    fixed = await harness.run("cve_list", "incremental")
    assert fixed["read_count"] == fixed["new_count"] == 1
    with harness.lab.owner() as connection:
        assert (
            required_row(
                connection.execute(
                    "SELECT cursor FROM cve.source_streams "
                    "WHERE source_id='cve_list' AND stream='main'"
                )
            )["cursor"]["git_commit"]
            == commit
        )


async def test_native_documents_index_priority_and_presence_history(
    git_harness: Harness, upstream: tuple[Path, Callable[[], str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from cve_common.database.engine import Database
    from cve_common.database.transactions import transaction
    from cve_common.jobs.execution import ExecutionContext
    from cve_common.jobs.repository import JobRepository
    from cve_common.v5 import revisions
    from cve_enricher.contracts import Configuration as EnrichmentConfiguration
    from cve_enricher.repository import enrich
    from cve_findings.repository import signals
    from cve_matcher.contracts import Request
    from cve_matcher.service import Service

    harness = git_harness
    configure(harness)
    root, publish = upstream
    identity = "CVE-2026-84001"
    path = write(root, identity)
    original = json.loads(path.read_text())
    original["containers"]["cna"]["metrics"] = [
        {
            "cvssV3_1": {
                "version": "3.1",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        }
    ]
    path.write_text(json.dumps(original))
    head = publish()
    run = await harness.run("cve_list")
    with harness.lab.owner() as connection:
        document = required_row(
            connection.execute(
                "SELECT * FROM cve.v5_current_documents WHERE identity=%s",
                (identity,),
            )
        )
        assert document["document"] == original and document["git_commit"] == head
        assert document["git_path"] == str(path.relative_to(root))
        assert document["git_blob_oid"] == git(root, "rev-parse", "HEAD:" + document["git_path"])
        assert not connection.execute(
            "SELECT 1 FROM cve.enrichment_assertions WHERE enrichment_revision_id=%s",
            (document["id"],),
        ).fetchone()
        stored = required_row(
            connection.execute(
                "SELECT result FROM cve.enrichment_revisions WHERE id=%s",
                (document["id"],),
            )
        )
        assert stored["result"] == {"storage": "v5-json"}
    database = Database(harness.lab.settings("matcher"))
    database.open()
    findings = Database(harness.lab.settings("findings_writer"))
    findings.open()
    enrichment = Database(harness.lab.settings("enricher"))
    enrichment.open()
    try:
        import cve_matcher.service as matching_service

        original_reader = revisions

        async def limited_reader(*args: Any, **kwargs: Any) -> Any:
            gate = (
                await args[0].execute(
                    sql_text("""
SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND mode='ShareLock'
 AND granted AND pid=pg_backend_pid() AND classid=0 AND objid=170017)
""")
                )
            ).scalar_one()
            assert gate, "Index batches must synchronize with inventory snapshot selection"
            if len(args[1]) > 1:
                raise ValueError("revision_context_bytes")
            return await original_reader(*args, **kwargs)

        monkeypatch.setattr(matching_service, "load_revisions", limited_reader)
        service = Service(database)
        repository = JobRepository(database, service.registry())
        for _ in range(100):
            job = await repository.claim(uuid4(), 30)
            if job is None:
                break
            context = ExecutionContext(
                repository, job, repository.registry.get(job.job_type, 1), asyncio.Event()
            )
            await service.handle(context, Request.model_validate(job.payload))
        else:
            raise AssertionError("Unbounded indexing queue")
        async with transaction(database) as s:
            indexed = (
                await s.execute(
                    sql_text(
                        "SELECT 1 FROM matching.indexed_revisions WHERE enrichment_revision_id=:id"
                    ),
                    {"id": document["id"]},
                )
            ).scalar_one()
            assert indexed == 1
        async with transaction(findings) as s:
            signal = await signals(s, identity)
            assert signal.cvss and signal.cvss["base_score"] == 9.8
            assert signal.kev_status == "unknown"
        # Even an explicitly requested historical backfill must retain native storage.
        async with transaction(enrichment) as s:
            result = await enrich(s, identity, run["job_id"], uuid4(), EnrichmentConfiguration())
            assert result.revision_id == document["id"] and not result.changed
        path.unlink()
        publish()
        await harness.run("cve_list", "incremental")
        with harness.lab.owner() as connection:
            removed = required_row(
                connection.execute(
                    "SELECT * FROM cve.v5_current_documents WHERE identity=%s",
                    (identity,),
                )
            )
        assert not removed["document_present"] and removed["id"] != document["id"]
        async with transaction(database) as s:
            history = {
                r["id"]: r["result"] for r in await revisions(s, [document["id"], removed["id"]])
            }
        assert history[document["id"]]["lifecycle"]["value"] == "published"
        assert history[removed["id"]]["lifecycle"]["value"] == "withdrawn"
        path.write_text(json.dumps(original))
        publish()
        await harness.run("cve_list", "incremental")
        with harness.lab.owner() as connection:
            restored = required_row(
                connection.execute(
                    "SELECT * FROM cve.v5_current_documents WHERE identity=%s",
                    (identity,),
                )
            )
        assert restored["document_present"] and restored["id"] == document["id"]
        assert restored["current_version"] == document["current_version"] + 2
    finally:
        await database.close()
        await findings.close()
        await enrichment.close()


async def test_native_page_and_index_queue_rollback_together(
    git_harness: Harness, upstream: tuple[Path, Callable[[], str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from cve_common.jobs.errors import ErrorCode, JobError
    from cve_common.jobs.models import Job
    from cve_importer import repository

    harness = git_harness
    configure(harness)
    root, publish = upstream
    identity = "CVE-2026-86001"
    write(root, identity)
    publish()
    original = repository.publish_native

    async def interrupt(*args: Any, **kwargs: Any) -> None:
        await original(*args, **kwargs)
        raise JobError(ErrorCode.TEMPORARY)

    monkeypatch.setattr(repository, "publish_native", interrupt)
    run_id = harness.schedule("cve_list")
    with pytest.raises(JobError):
        await harness.execute()
    with harness.lab.owner() as connection:
        run = required_row(
            connection.execute("SELECT * FROM cve.import_runs WHERE id=%s", (run_id,))
        )
        job = Job.model_validate(
            required_row(
                connection.execute("SELECT * FROM automation.jobs WHERE id=%s", (run["job_id"],))
            )
        )
        assert run["read_count"] == 0 and run["progress"] == {}
        assert not connection.execute(
            "SELECT 1 FROM cve.source_records WHERE external_id=%s", (identity,)
        ).fetchone()
        assert not connection.execute(
            "SELECT 1 FROM cve.enrichment_identities WHERE identity=%s", (identity,)
        ).fetchone()
        assert not connection.execute(
            "SELECT 1 FROM automation.jobs WHERE job_type='matching.index_v5_batch' "
            "AND correlation_id=%s",
            (run["correlation_id"],),
        ).fetchone()
    await harness.repository.finish(job, "retry", ErrorCode.TEMPORARY)
    with harness.lab.owner() as connection:
        connection.execute(
            "UPDATE automation.jobs SET scheduled_at=clock_timestamp() WHERE id=%s", (job.id,)
        )
    monkeypatch.setattr(repository, "publish_native", original)
    await harness.execute()
    assert harness.row(run_id)["effective_status"] == "completed"
    with harness.lab.owner() as connection:
        assert connection.execute(
            "SELECT 1 FROM cve.v5_current_documents WHERE identity=%s", (identity,)
        ).fetchone()
