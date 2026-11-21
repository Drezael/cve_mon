"""Real PostgreSQL, worker fencing and all five adapters against deterministic wire fixtures."""

import asyncio
import hashlib
import io
import json
import zipfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from cve_common.database.engine import Database
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker, WorkerSettings
from cve_importer.contracts import Configuration, Request
from cve_importer.service import Service
from cve_importer.transport import Transport

from scripts.database import manage as db
from tests.cve_importer import fixtures as f
from tests.cve_importer.conftest import Lab
from tests.database.helpers import required_row

pytestmark = pytest.mark.cve_importer


def archive(records: list[dict[str, Any]], source: str = "osv") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as z:
        for row in records:
            key = row["cveMetadata"]["cveId"] if source == "cve_list" else row["id"]
            entry = zipfile.ZipInfo(key + ".json", date_time=(2026, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(entry, json.dumps(row))
    return output.getvalue()


def wire_response(
    status: int, *, content: bytes | str = b"", headers: dict[str, str] | None = None
) -> httpx.Response:
    raw = content.encode() if isinstance(content, str) else content
    return httpx.Response(status, stream=httpx.ByteStream(raw), headers=headers)


class Wire:
    def __init__(self) -> None:
        self.cve = [f.cve()]
        self.nvd = [f.nvd()]
        self.kev = [f.kev()]
        self.ubuntu = [f.ubuntu()]
        self.osv = [f.osv()]
        self.tag = "cve_2026-11-07_2100Z"
        self.catalog_version = "2026.11.07"
        self.requests: list[httpx.Request] = []
        self.broken: str | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if self.broken and self.broken in path:
            return wire_response(503, headers={"Retry-After": "0"})
        if request.url.host == "api.github.com":
            baseline = archive(self.cve, "cve_list")
            delta = archive([], "cve_list")
            day = self.tag[4:14]
            items = [
                (day + "_all_CVEs_at_midnight.zip.zip", baseline),
                (day + "_delta_CVEs_at_2100Z.zip", delta),
            ]
            value: Any = [
                {
                    "tag_name": self.tag,
                    "draft": False,
                    "prerelease": False,
                    "assets": [
                        {
                            "name": name,
                            "size": len(raw),
                            "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                            "browser_download_url": "https://github.com/CVEProject/cvelistV5/rele"
                            "ases/download/" + self.tag + "/" + name,
                        }
                        for name, raw in items
                    ],
                }
            ]
        elif request.url.host == "github.com":
            raw = archive(self.cve if "all_CVEs" in path else [], "cve_list")
            return wire_response(200, content=raw, headers={"Content-Type": "application/zip"})
        elif request.url.host == "services.nvd.nist.gov":
            offset = int(request.url.params["startIndex"])
            limit = int(request.url.params["resultsPerPage"])
            value = {
                "format": "NVD_CVE",
                "version": "2.0",
                "timestamp": "2026-11-07T12:00:00.000",
                "startIndex": offset,
                "resultsPerPage": min(limit, len(self.nvd) - offset),
                "totalResults": len(self.nvd),
                "vulnerabilities": [{"cve": v} for v in self.nvd[offset : offset + limit]],
            }
        elif request.url.host == "www.cisa.gov":
            value = f.catalog(self.kev, self.catalog_version)
        elif request.url.host == "ubuntu.com":
            key = "notices" if "notices" in path else "cves"
            rows = (
                [f.ubuntu("USN-1234-1")]
                if key == "notices"
                else self.ubuntu
                if request.url.params["cve_status"] == "active"
                else []
            )
            offset = int(request.url.params["offset"])
            value = {
                key: rows[offset : offset + 20],
                "offset": offset,
                "limit": 20,
                "total_results": len(rows),
            }
        elif path.endswith("all.zip"):
            return wire_response(
                200, content=archive(self.osv), headers={"Content-Type": "application/zip"}
            )
        elif path.endswith("modified_id.csv"):
            csv_body = "\n".join(v["modified"] + "," + v["id"] for v in self.osv)
            return wire_response(200, content=csv_body, headers={"Content-Type": "text/csv"})
        else:
            value = next(v for v in self.osv if path.endswith(v["id"] + ".json"))
        return wire_response(
            200, content=json.dumps(value).encode(), headers={"Content-Type": "application/json"}
        )


class Harness:
    def __init__(self, lab: Lab, directory: Path) -> None:
        self.lab = lab
        self.wire = Wire()
        self.configuration = Configuration(
            enabled=["cve_list", "nvd", "cisa_kev", "ubuntu", "osv"],
            cve_list_transport="release",
            epss_enabled=True,
            osv_ecosystems=["PyPI"],
            minimum_delay=0,
            page_size=2,
            batch_size=2,
        )
        self.database = Database(lab.settings())
        self.database.open()
        self.transport = Transport(
            self.configuration,
            directory,
            client=httpx.AsyncClient(transport=httpx.MockTransport(self.wire)),
        )

        async def no_wait(source: str) -> None:
            pass

        self.transport.pace = no_wait  # type: ignore[method-assign]
        self.service = Service(self.database, self.configuration, self.transport)
        self.repository = JobRepository(self.database, self.service.registry())

    def schedule(self, source: str, mode: str = "initial", key: str | None = None) -> UUID:
        with db.connect(self.lab.config, "api_security") as c:
            result = required_row(
                c.execute(
                    "SELECT cve.schedule_import(%s,%s,%s::jsonb,%s,%s) AS id",
                    (
                        source,
                        mode,
                        json.dumps({"configuration": self.configuration.model_dump()}),
                        key or str(uuid4()),
                        uuid4(),
                    ),
                )
            )
        run_id = UUID(str(result["id"]))
        if source == "nvd":
            with self.lab.owner() as c:
                c.execute(
                    "UPDATE cve.import_runs SET created_at='1970-01-02T00:00:00Z' WHERE id=%s",
                    (run_id,),
                )
        return run_id

    def row(self, run_id: UUID) -> dict[str, Any]:
        with self.lab.owner() as c:
            return required_row(
                c.execute("SELECT * FROM cve.import_run_status WHERE id=%s", (run_id,))
            )

    async def execute(self) -> Any:
        async with asyncio.timeout(3):
            job = await self.repository.claim(uuid4(), 30)
            while job is None:
                await asyncio.sleep(0.01)
                job = await self.repository.claim(uuid4(), 30)
        definition = self.service.registry().get(job.job_type, 1)
        context = ExecutionContext(self.repository, job, definition, asyncio.Event())
        return await self.service.handle(context, Request.model_validate(job.payload))

    async def run(self, source: str, mode: str = "initial") -> dict[str, Any]:
        run_id = self.schedule(source, mode)
        await self.execute()
        row = self.row(run_id)
        assert row["effective_status"] == "completed", row
        return row


@pytest.fixture
async def harness(import_lab: Lab, tmp_path: Path) -> AsyncIterator[Harness]:
    value = Harness(import_lab, tmp_path)
    try:
        yield value
    finally:
        await value.transport.close()
        await value.database.close()


@pytest.mark.parametrize(
    "source,expected", [("cve_list", 1), ("nvd", 1), ("cisa_kev", 2), ("ubuntu", 2), ("osv", 1)]
)
async def test_e2e_initial_repeat_revision_and_isolation(
    harness: Harness, source: str, expected: int
) -> None:
    first = await harness.run(source)
    repeat = await harness.run(source)
    assert first["read_count"] == expected
    assert repeat["new_count"] == repeat["changed_count"] == 0
    assert repeat["unchanged_count"] == expected
    with harness.lab.owner() as c:
        rows = c.execute(
            "SELECT * FROM cve.current_source_records WHERE source_id=%s AND last_seen_run=%s",
            (source, repeat["id"]),
        ).fetchall()
        assert len(rows) == expected
        assert all(r["original_json"] for r in rows)
        assert required_row(c.execute("SELECT count(*) AS n FROM inventory.servers"))["n"] == 0
        assert required_row(c.execute("SELECT count(*) AS n FROM findings.findings"))["n"] == 0
        assert required_row(c.execute("SELECT count(*) AS n FROM cve.records"))["n"] == 0
        assert c.execute(
            "SELECT 1 FROM automation.event_outbox WHERE "
            "payload->>'run_id'=%s AND event_type='cve.source.completed'",
            (str(first["id"]),),
        ).fetchone()
    if source == "osv":
        harness.wire.osv[0]["withdrawn"] = "2026-11-07T12:00:00Z"
        changed = await harness.run(source, "reconcile")
        assert changed["changed_count"] == 1
    if source == "cve_list":
        harness.wire.cve = [f.cve(state="REJECTED")]
        changed = await harness.run(source, "reconcile")
        assert changed["changed_count"] == 1


async def test_partial_keeps_valid_records_without_cursor(harness: Harness) -> None:
    harness.wire.osv = [
        f.osv("GHSA-valid-record-0001"),
        {"id": "GHSA-bad-record-0002", "schema_version": "9.0"},
    ]
    with harness.lab.owner() as c:
        before = c.execute("SELECT cursor FROM cve.source_streams WHERE source_id='osv'").fetchall()
    run_id = harness.schedule("osv", "reconcile")
    result = await harness.execute()
    assert result.status == "partial"
    assert harness.row(run_id)["error_count"] == 1
    with harness.lab.owner() as c:
        assert c.execute(
            "SELECT 1 FROM cve.source_records WHERE external_id='GHSA-valid-record-0001'"
        ).fetchone()
        assert (
            c.execute("SELECT cursor FROM cve.source_streams WHERE source_id='osv'").fetchall()
            == before
        )


async def test_native_same_source_serialization(harness: Harness) -> None:
    key = str(uuid4())
    run_id = harness.schedule("cisa_kev", key=key)
    assert harness.schedule("cisa_kev", key=key) == run_id
    import psycopg

    with pytest.raises(psycopg.Error):
        harness.schedule("cisa_kev", key=str(uuid4()))
    await harness.execute()


async def test_kev_complete_removal_and_regression_guard(harness: Harness) -> None:
    harness.wire.kev = [f.kev("CVE-2026-20001"), f.kev("CVE-2026-20002")]
    await harness.run("cisa_kev", "reconcile")
    harness.wire.kev = [f.kev("CVE-2026-20001")]
    harness.wire.catalog_version = "2026.11.08"
    await harness.run("cisa_kev", "reconcile")
    with harness.lab.owner() as c:
        assert not required_row(
            c.execute(
                "SELECT present FROM cve.source_records WHERE "
                "source_id='cisa_kev' AND external_id='CVE-2026-20002'"
            )
        )["present"]
    harness.wire.kev = []
    run_id = harness.schedule("cisa_kev", "reconcile")
    assert (await harness.execute()).status == "partial"
    assert harness.row(run_id)["error_count"] == 1


async def test_pagination_incremental_and_original_provenance(harness: Harness) -> None:
    # Keep this incremental fixture inside the real overlap window on any test date.
    harness.wire.osv[0]["modified"] = (
        (datetime.now(UTC) - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    )
    harness.wire.nvd = [f.nvd("CVE-2026-3000" + str(i)) for i in range(5)]
    row = await harness.run("nvd", "reconcile")
    assert row["read_count"] == 5
    assert len([r for r in harness.wire.requests if r.url.host == "services.nvd.nist.gov"]) == 3
    await harness.run("osv", "initial")
    # The incremental upper bound follows the real scheduling time, the fixture is inside overlap.
    row = await harness.run("osv", "incremental")
    assert row["unchanged_count"] == 1
    with harness.lab.owner() as c:
        origins = c.execute(
            "SELECT a.location FROM cve.source_observations o JOIN "
            "cve.source_artifacts a ON a.id=o.artifact_id WHERE o.run_id=%s",
            (row["id"],),
        ).fetchall()
        assert all(r["location"].endswith(".json") for r in origins)


async def test_performance_bounded_bulk(harness: Harness) -> None:
    harness.configuration = harness.configuration.model_copy(update={"batch_size": 250})
    harness.service.configuration = harness.configuration
    harness.wire.osv = [f.osv("GHSA-performance-" + str(i)) for i in range(1000)]
    import time

    started = time.monotonic()
    row = await harness.run("osv", "reconcile")
    assert row["read_count"] == 1000
    assert time.monotonic() - started < 90
    assert row["write_ms"] > 0 and row["parse_ms"] > 0


async def test_recovery_resumes_committed_batch(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cve_common.jobs.errors import ErrorCode, JobError
    from cve_importer.adapters import Adapters

    harness.wire.osv = [f.osv("GHSA-recovery-" + str(i)) for i in range(5)]
    run_id = harness.schedule("osv", "reconcile")
    original = Adapters.next
    calls = 0

    async def interrupted(adapter: Adapters, progress: dict[str, Any]) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise JobError(ErrorCode.NETWORK)
        return await original(adapter, progress)

    monkeypatch.setattr(Adapters, "next", interrupted)
    job = await harness.repository.claim(uuid4(), 30)
    assert job is not None
    settings = WorkerSettings(
        service_name="cve-importer", app_env="test", database=harness.lab.settings()
    )
    await Worker(harness.repository, settings).execute(job, asyncio.Event())
    row = harness.row(run_id)
    assert row["progress"]["offset"] == 2 and row["read_count"] == 2
    with harness.lab.owner() as c:
        assert (
            required_row(c.execute("SELECT status FROM automation.jobs WHERE id=%s", (job.id,)))[
                "status"
            ]
            == "retry_pending"
        )
        c.execute(
            "UPDATE automation.jobs SET scheduled_at=clock_timestamp() WHERE id=%s", (job.id,)
        )
    monkeypatch.setattr(Adapters, "next", original)
    await harness.execute()
    row = harness.row(run_id)
    assert row["effective_status"] == "completed" and row["read_count"] == 5
    with harness.lab.owner() as c:
        assert (
            required_row(
                c.execute(
                    "SELECT count(*) AS n FROM cve.source_observations WHERE run_id=%s", (run_id,)
                )
            )["n"]
            == 5
        )


async def test_stale_fence_rolls_back_source_changes(harness: Harness) -> None:
    from cve_common.jobs.errors import LeaseLost

    run_id = harness.schedule("cisa_kev", "reconcile")
    job = await harness.repository.claim(uuid4(), 30)
    assert job is not None
    definition = harness.service.registry().get(job.job_type, 1)
    context = ExecutionContext(harness.repository, job, definition, asyncio.Event())
    with harness.lab.owner() as c:
        c.execute(
            "UPDATE automation.jobs SET lease_until=clock_timestamp()-"
            "interval '1 second' WHERE id=%s",
            (job.id,),
        )
    with pytest.raises(LeaseLost):
        await harness.service.handle(context, Request(run_id=run_id))
    assert harness.row(run_id)["read_count"] == 0
    assert await harness.repository.recover() >= 1
    with harness.lab.owner() as c:
        c.execute(
            "UPDATE automation.jobs SET scheduled_at=clock_timestamp() WHERE id=%s", (job.id,)
        )
    await harness.execute()
    assert harness.row(run_id)["effective_status"] == "completed"


async def test_concurrency_independent_sources(harness: Harness) -> None:
    first = harness.schedule("cisa_kev", "reconcile")
    second = harness.schedule("ubuntu", "reconcile")
    await asyncio.gather(harness.execute(), harness.execute())
    assert (
        harness.row(first)["effective_status"]
        == harness.row(second)["effective_status"]
        == "completed"
    )


async def test_revision_native_immutability_and_original_hash(harness: Harness) -> None:
    import psycopg

    harness.wire.osv = [f.osv("GHSA-native-immutability")]
    row = await harness.run("osv", "reconcile")
    with harness.lab.owner() as c:
        revision = required_row(
            c.execute("SELECT * FROM cve.source_revisions WHERE run_id=%s LIMIT 1", (row["id"],))
        )
        assert len(revision["original_record_sha256"]) == 32
        assert revision["content_sha256"] != revision["original_record_sha256"]
    for query in [
        "UPDATE cve.source_revisions SET original_json='{}' WHERE id=%s",
        "DELETE FROM cve.source_revisions WHERE id=%s",
    ]:
        with db.connect(harness.lab.config, "importer") as c, pytest.raises(psycopg.Error):
            c.execute(query, (revision["id"],))


async def test_backup_restore_source_revisions(harness: Harness, tmp_path: Path) -> None:
    await harness.run("cisa_kev", "reconcile")
    target = tmp_path / "backup"
    db.backup(harness.lab.config, target)
    report = db.restore_test(harness.lab.config, target)
    assert report


async def test_failure_outbox_and_explicit_new_run(harness: Harness) -> None:
    from cve_common.jobs.errors import ErrorCode

    run_id = harness.schedule("cisa_kev", "reconcile")
    job = await harness.repository.claim(uuid4(), 30)
    assert job is not None
    assert await harness.repository.finish(job, "failed", ErrorCode.PERMANENT)
    assert harness.row(run_id)["effective_status"] == "failed"
    with harness.lab.owner() as c:
        event = required_row(
            c.execute(
                "SELECT payload FROM automation.event_outbox WHERE "
                "event_type='cve.source.failed' AND payload->>'run_id'=%s",
                (str(run_id),),
            )
        )
        assert set(event["payload"]) <= {
            "run_id",
            "source_id",
            "code",
            "record_id",
            "revision_id",
            "external_id",
        }
        assert c.execute(
            "SELECT 1 FROM security.audit_log WHERE action='cve.source.failed' AND object_id=%s",
            (str(run_id),),
        ).fetchone()
    await harness.run("cisa_kev", "reconcile")


async def test_cve_delta_gap_has_no_success_cursor(harness: Harness) -> None:
    with harness.lab.owner() as c:
        before = c.execute(
            "SELECT cursor FROM cve.source_streams WHERE source_id='cve_list'"
        ).fetchall()
    harness.wire.tag = "cve_2026-11-08_2100Z"
    run_id = harness.schedule("cve_list", "incremental")
    assert (await harness.execute()).status == "partial"
    with harness.lab.owner() as c:
        assert (
            c.execute("SELECT cursor FROM cve.source_streams WHERE source_id='cve_list'").fetchall()
            == before
        )
        assert c.execute("SELECT 1 FROM cve.import_errors WHERE run_id=%s", (run_id,)).fetchone()


async def test_nvd_invalid_record_keeps_valid_neighbor(harness: Harness) -> None:
    harness.wire.nvd = [f.nvd("CVE-2026-40001"), {"id": "CVE-2026-40002"}]
    run_id = harness.schedule("nvd", "reconcile")
    assert (await harness.execute()).status == "partial"
    row = harness.row(run_id)
    assert row["read_count"] == 2 and row["error_count"] == 1
    with harness.lab.owner() as c:
        assert c.execute(
            "SELECT 1 FROM cve.source_records WHERE source_id='nvd' AND "
            "external_id='CVE-2026-40001'"
        ).fetchone()


async def test_osv_stale_revision_and_reconcile(harness: Harness) -> None:
    value = f.osv("GHSA-stale-correction")
    observed = datetime.now(UTC) - timedelta(minutes=5)
    value["modified"] = observed.isoformat().replace("+00:00", "Z")
    harness.wire.osv = [value]
    await harness.run("osv", "reconcile")
    value["modified"] = (observed - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    value["summary"] = "Historical correction"
    stale = await harness.run("osv", "incremental")
    assert stale["stale_count"] == 1
    with harness.lab.owner() as c:
        current = required_row(
            c.execute(
                "SELECT original_json FROM cve.current_source_records WHERE "
                "source_id='osv' AND external_id='GHSA-stale-correction'"
            )
        )
        assert "summary" not in current["original_json"]
    await harness.run("osv", "reconcile")
    with harness.lab.owner() as c:
        current = required_row(
            c.execute(
                "SELECT original_json FROM cve.current_source_records WHERE "
                "source_id='osv' AND external_id='GHSA-stale-correction'"
            )
        )
        assert current["original_json"]["summary"] == "Historical correction"


async def test_concurrency_same_source_native_race(harness: Harness) -> None:
    import threading

    import psycopg

    barrier = threading.Barrier(2)

    def compete() -> UUID | None:
        barrier.wait(timeout=10)
        try:
            return harness.schedule("cisa_kev", "reconcile")
        except psycopg.errors.ObjectNotInPrerequisiteState:
            return None

    results = await asyncio.gather(asyncio.to_thread(compete), asyncio.to_thread(compete))
    assert sum(value is not None for value in results) == 1
    await harness.execute()


async def test_operator_resume_large_import_checkpoint(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cve_common.jobs.errors import ErrorCode, JobError
    from cve_importer.adapters import Adapters

    from scripts.cve_importer.manage import resume

    harness.wire.osv = [f.osv("GHSA-budget-resume-" + str(i)) for i in range(5)]
    run_id = harness.schedule("osv", "reconcile")
    original = Adapters.next
    calls = 0

    async def exhausted(adapter: Adapters, progress: dict[str, Any]) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise JobError(ErrorCode.PERMANENT)
        return await original(adapter, progress)

    monkeypatch.setattr(Adapters, "next", exhausted)
    job = await harness.repository.claim(uuid4(), 30)
    assert job is not None
    settings = WorkerSettings(
        service_name="cve-importer", app_env="test", database=harness.lab.settings()
    )
    await Worker(harness.repository, settings).execute(job, asyncio.Event())
    assert harness.row(run_id)["effective_status"] == "failed"
    assert harness.row(run_id)["progress"]["offset"] == 2
    new_job = resume(harness.lab.config, run_id)
    assert new_job != job.id
    with pytest.raises(ValueError):
        resume(harness.lab.config, run_id)
    monkeypatch.setattr(Adapters, "next", original)
    await harness.execute()
    row = harness.row(run_id)
    assert row["effective_status"] == "completed" and row["read_count"] == 5
    assert row["job_id"] == new_job
