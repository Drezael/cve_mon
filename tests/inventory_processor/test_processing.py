"""Real acceptance to fenced job to immutable snapshot, including native database denial."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from cve_common.database.engine import Database
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker
from cve_inventory.processing import Submission, handle, registry
from cve_inventory.settings import InventorySettings

from tests.database.helpers import required_row
from tests.inventory_processor.test_normalization import sample
from tests.inventory_upload.integration.conftest import Browser, provision, technical

pytestmark = pytest.mark.inventory_processor


async def submit(
    browser: Browser, value: dict[str, Any] | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    upload = await provision(browser)
    value = value or sample()
    value["server_id"] = upload.server["id"]
    response = await technical(browser, upload, json.dumps(value).encode())
    assert response.status_code == 202, response.text
    return response.json(), value


async def drain(browser: Browser, concurrency: int = 1) -> None:
    settings = browser.lab.database("inventory_processor").model_copy(
        update={"statement_timeout_ms": 30000}
    )
    database = Database(settings)
    database.open()
    repository = JobRepository(database, registry())
    try:
        jobs = []
        for _ in range(100):
            job = await repository.claim(uuid4(), 30)
            if job is None:
                break
            jobs.append(job)
        semaphore = asyncio.Semaphore(concurrency)

        async def run(job: Any) -> None:
            async with semaphore:
                worker = Worker(repository, InventorySettings(app_env="test", database=settings))
                await worker.execute(job, asyncio.Event())

        await asyncio.gather(*(run(job) for job in jobs))
        from tests.application.settle import pending

        for _ in range(200):
            if not pending(browser, repository.registry.names):
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("Inventory background worker did not settle")

    finally:
        await database.close()


@pytest.mark.asyncio
async def test_e2e_immutable_snapshot_and_outbox(browser: Browser) -> None:
    receipt, value = await submit(browser)
    with browser.lab.owner() as c:
        before = c.execute(
            "SELECT to_jsonb(s) AS value FROM inventory.servers s WHERE id=%s",
            (receipt["server_id"],),
        ).fetchone()
    await drain(browser)
    with browser.lab.owner() as c:
        state = c.execute(
            "SELECT * FROM inventory.processing_status WHERE submission_id=%s",
            (receipt["submission_id"],),
        ).fetchone()
        assert state["status"] == "completed", state
        assert state["job_status"] == "succeeded"
        snapshot = c.execute(
            "SELECT * FROM inventory.snapshots WHERE id=%s", (state["snapshot_id"],)
        ).fetchone()
        assert snapshot["package_count"] == 1
        assert snapshot["original_json"] == value
        assert snapshot["normalizer_version"] == "inventory-1"
        assert (
            c.execute(
                "SELECT snapshot_id FROM inventory.server_current_snapshots WHERE server_id=%s",
                (receipt["server_id"],),
            ).fetchone()["snapshot_id"]
            == state["snapshot_id"]
        )
        assert (
            c.execute(
                "SELECT to_jsonb(s) AS value FROM inventory.servers s WHERE id=%s",
                (receipt["server_id"],),
            ).fetchone()
            == before
        )
        events = c.execute(
            "SELECT event_type FROM automation.event_outbox WHERE payload->>'submission_id'=%s",
            (receipt["submission_id"],),
        ).fetchall()
        assert {r["event_type"] for r in events} >= {
            "inventory.processing_started",
            "inventory.snapshot_created",
            "inventory.current_changed",
            "inventory.processing_completed",
        }
    await drain(browser)
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT count(*) AS n FROM inventory.snapshots WHERE inventory_id=%s",
                (value["inventory_id"],),
            ).fetchone()["n"]
            == 1
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("concurrency", [1, 2, 4])
async def test_current_history_and_global_identity(browser: Browser, concurrency: int) -> None:
    upload = await provision(browser)
    base = sample()
    base["server_id"] = upload.server["id"]
    now = datetime.now(UTC)
    values = []
    for age, status in [
        (60, "complete"),
        (30, "complete"),
        (30, "complete"),
        (90, "complete"),
        (10, "partial"),
        (-60, "complete"),
    ]:
        value = json.loads(json.dumps(base))
        value.update(
            inventory_id=str(uuid4()),
            captured_at=(now - timedelta(seconds=age)).isoformat(),
            collection_status=status,
        )
        if status == "partial":
            value["services"] = {"status": "failed", "error_code": "collect_failed"}
        response = await technical(browser, upload, json.dumps(value).encode())
        assert response.status_code == 202, response.text
        values.append(value)
    # Another receipt of exactly the same business inventory must not create another snapshot.
    duplicate = await technical(
        browser, upload, json.dumps(values[1], indent=2).encode(), key="other-receipt"
    )
    assert duplicate.status_code == 202
    await drain(browser, concurrency)
    with browser.lab.owner() as c:
        history = c.execute(
            "SELECT inventory_id FROM inventory.snapshots WHERE server_id=%s",
            (upload.server["id"],),
        ).fetchall()
        assert len(history) == 6
        current = c.execute(
            "SELECT inventory_id FROM inventory.current_snapshots WHERE server_id=%s",
            (upload.server["id"],),
        ).fetchone()
        expected = max(
            (
                v
                for v in values
                if v["collection_status"] == "complete" and v["captured_at"] <= now.isoformat()
            ),
            key=lambda v: (v["captured_at"], v["inventory_id"]),
        )
        assert str(current["inventory_id"]) == expected["inventory_id"]
        assert (
            c.execute(
                "SELECT count(DISTINCT snapshot_id) AS n FROM "
                "inventory.submission_processing p JOIN inventory.submissions s "
                "ON s.id=p.submission_id WHERE s.inventory_id=%s",
                (values[1]["inventory_id"],),
            ).fetchone()["n"]
            == 1
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "table",
    [
        "snapshots",
        "packages",
        "services",
        "containers",
        "images",
        "kernels",
        "collection_sections",
        "operating_systems",
    ],
)
async def test_sealed_rows_deny_owner_mutation(browser: Browser, table: str) -> None:
    import psycopg

    receipt, _ = await submit(browser)
    await drain(browser)
    # Include INSERT after commit, even for a previously empty inventory section.
    with browser.lab.owner() as c:
        sid = c.execute(
            "SELECT snapshot_id FROM inventory.submission_processing WHERE submission_id=%s",
            (receipt["submission_id"],),
        ).fetchone()["snapshot_id"]
    from psycopg import sql

    with browser.lab.owner() as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        if table == "containers":
            c.execute(
                "INSERT INTO "
                "inventory.containers(snapshot_id,container_id,image_reference,sta"
                "te) VALUES(%s,'later','late:tag','running')",
                (sid,),
            )
        else:
            # All selected tables have at least one row in the fixture.
            key = "id" if table == "snapshots" else "snapshot_id"
            c.execute(
                sql.SQL("DELETE FROM inventory.{} WHERE {}=%s").format(
                    sql.Identifier(table), sql.Identifier(key)
                ),
                (sid,),
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "table,operation",
    [
        ("servers", "UPDATE"),
        ("server_groups", "INSERT"),
        ("server_group_memberships", "DELETE"),
        ("security.user_server_access", "UPDATE"),
        ("security.api_tokens", "INSERT"),
        ("security.technical_certificates", "UPDATE"),
    ],
)
async def test_native_permissions(browser: Browser, table: str, operation: str) -> None:
    from scripts.database import manage as db

    qualified = table if "." in table else "inventory." + table
    with db.connect(browser.lab.config, "inventory_processor") as c:
        assert not required_row(
            c.execute(
                "SELECT has_table_privilege(current_user,%s,%s) AS allowed", (qualified, operation)
            )
        )["allowed"]
        if operation == "UPDATE":
            assert not required_row(
                c.execute(
                    "SELECT has_any_column_privilege(current_user,%s,'UPDATE') AS allowed",
                    (qualified,),
                )
            )["allowed"]


@pytest.mark.asyncio
async def test_archive_historical_and_no_current(browser: Browser) -> None:
    receipt, _ = await submit(browser)
    with browser.lab.owner() as c:
        c.execute(
            "UPDATE inventory.servers SET "
            "status='archived',archived_at=clock_timestamp(),version=version+1"
            " WHERE id=%s",
            (receipt["server_id"],),
        )
    await drain(browser)
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT status FROM inventory.processing_status WHERE submission_id=%s",
                (receipt["submission_id"],),
            ).fetchone()["status"]
            == "completed"
        )
        assert (
            c.execute(
                "SELECT snapshot_id FROM inventory.server_current_snapshots WHERE server_id=%s",
                (receipt["server_id"],),
            ).fetchone()
            is None
        )


@pytest.mark.asyncio
async def test_backfill_idempotent(browser: Browser) -> None:
    from scripts.database import manage as db

    receipt, _ = await submit(browser)
    # Simulate an accepted pre-Phase-14 row without its scheduling trigger; only in own DB.
    with browser.lab.owner() as c:
        job = required_row(
            c.execute(
                "DELETE FROM inventory.submission_processing "
                "WHERE submission_id=%s RETURNING job_id",
                (receipt["submission_id"],),
            )
        )["job_id"]
        c.execute("DELETE FROM automation.jobs WHERE id=%s", (job,))
    with db.connect(browser.lab.config, "inventory_processor") as c:
        assert required_row(c.execute("SELECT inventory.backfill(100) AS n"))["n"] == 1
        assert required_row(c.execute("SELECT inventory.backfill(100) AS n"))["n"] == 0
    await drain(browser)
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT count(*) AS n FROM inventory.snapshots WHERE submission_id=%s",
                (receipt["submission_id"],),
            ).fetchone()["n"]
            == 1
        )
        assert (
            c.execute(
                "SELECT job_id FROM inventory.submission_processing WHERE submission_id=%s",
                (receipt["submission_id"],),
            ).fetchone()["job_id"]
            != job
        )


@pytest.mark.asyncio
async def test_large_package_inventory(browser: Browser, record_property: Any) -> None:
    import time

    value = sample()
    value["packages"]["items"] = [
        {
            "name": f"package-{i}",
            "version": "2:1.0~rc1-3ubuntu1",
            "architecture": "amd64",
            "package_manager": "dpkg",
        }
        for i in range(10000)
    ]
    value["images"]["items"] = [
        {
            "image_id": "sha256:" + f"{i:064x}",
            "references": [f"registry.example.test:5000/app:{i}"],
            "repo_digests": [],
        }
        for i in range(600)
    ]
    value["containers"]["items"] = [
        {
            "container_id": f"{i:064x}",
            "image_reference": f"registry.example.test:5000/app:{i}",
            "image_id": "sha256:" + f"{i:064x}",
            "state": "stopped",
            "collection_status": "complete",
        }
        for i in range(600)
    ]
    receipt, _ = await submit(browser, value)
    begin = time.monotonic()
    await drain(browser)
    elapsed = time.monotonic() - begin
    record_property("processing_seconds_10000_packages", elapsed)
    assert elapsed < 60
    with browser.lab.owner() as c:
        state = c.execute(
            "SELECT snapshot_id,status FROM inventory.processing_status WHERE submission_id=%s",
            (receipt["submission_id"],),
        ).fetchone()
        assert state["status"] == "completed", state
        assert (
            c.execute(
                "SELECT count(*) AS n FROM inventory.packages WHERE "
                "snapshot_id=%s AND epoch='2' AND release='3ubuntu1'",
                (state["snapshot_id"],),
            ).fetchone()["n"]
            == 10000
        )


@pytest.mark.asyncio
async def test_rollback_and_stale_fence(browser: Browser, monkeypatch: pytest.MonkeyPatch) -> None:
    from cve_common.jobs.errors import LeaseLost
    from cve_inventory import processing

    receipt, value = await submit(browser)
    database = Database(browser.lab.database("inventory_processor"))
    database.open()
    repository = JobRepository(database, registry())
    try:
        job = await repository.claim(uuid4(), 30)
        assert job is not None
        original = processing.bulk

        async def fail(s: Any, sql: str, rows: Any) -> None:
            if "inventory.services" in sql:
                raise RuntimeError("injected database boundary")
            await original(s, sql, rows)

        monkeypatch.setattr(processing, "bulk", fail)
        with pytest.raises(RuntimeError, match="injected"):
            await handle(
                ExecutionContext(repository, job, registry().get(job.job_type, 1), asyncio.Event()),
                Submission.model_validate(job.payload),
            )
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT id FROM inventory.snapshots WHERE inventory_id=%s",
                    (value["inventory_id"],),
                ).fetchone()
                is None
            )
            c.execute(
                "UPDATE automation.jobs SET "
                "lease_until=clock_timestamp()-interval '1 second' WHERE id=%s",
                (job.id,),
            )
        monkeypatch.setattr(processing, "bulk", original)
        with pytest.raises(LeaseLost):
            await handle(
                ExecutionContext(repository, job, registry().get(job.job_type, 1), asyncio.Event()),
                Submission.model_validate(job.payload),
            )
        assert await repository.recover() >= 1
        with browser.lab.owner() as c:
            c.execute(
                "UPDATE automation.jobs SET scheduled_at=clock_timestamp() WHERE id=%s", (job.id,)
            )
        await drain(browser)
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT status FROM inventory.processing_status WHERE submission_id=%s",
                    (receipt["submission_id"],),
                ).fetchone()["status"]
                == "completed"
            )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_retry_exhaustion_and_failed_event(
    browser: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cve_inventory import processing

    receipt, _ = await submit(browser)

    async def timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise TimeoutError()

    from cve_inventory.validation import prepare as original_prepare

    monkeypatch.setattr(processing, "prepare", timeout)
    database = Database(browser.lab.database("inventory_processor"))
    database.open()
    repo = JobRepository(database, registry())
    worker = Worker(
        repo,
        InventorySettings(app_env="test", database=browser.lab.database("inventory_processor")),
    )
    try:
        for attempt in range(3):
            job = await repo.claim(uuid4(), 30)
            assert job is not None
            await worker.execute(job, asyncio.Event())
            with browser.lab.owner() as c:
                state = c.execute(
                    "SELECT * FROM inventory.processing_status WHERE submission_id=%s",
                    (receipt["submission_id"],),
                ).fetchone()
                assert state["status"] == ("failed" if attempt == 2 else "accepted"), state
                c.execute(
                    "UPDATE automation.jobs SET scheduled_at=clock_timestamp() WHERE id=%s",
                    (job.id,),
                )
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT count(*) AS n FROM automation.event_outbox WHERE "
                    "event_type='inventory.processing_failed' AND "
                    "payload->>'submission_id'=%s",
                    (receipt["submission_id"],),
                ).fetchone()["n"]
                == 1
            )
            assert (
                c.execute(
                    "SELECT snapshot_id FROM inventory.submission_processing WHERE "
                    "submission_id=%s",
                    (receipt["submission_id"],),
                ).fetchone()["snapshot_id"]
                is None
            )
        monkeypatch.setattr(processing, "prepare", original_prepare)
        from scripts.database import manage as db

        assert job is not None
        with db.connect(browser.lab.config, "api_security") as c:
            replay = required_row(
                c.execute("SELECT automation.control_job(%s,'replay') AS id", (job.id,))
            )["id"]
        await drain(browser)
        with browser.lab.owner() as c:
            state = c.execute(
                "SELECT * FROM inventory.processing_status WHERE submission_id=%s",
                (receipt["submission_id"],),
            ).fetchone()
            assert state["status"] == "completed" and state["job_id"] == replay
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_permanent_rejection(browser: Browser, monkeypatch: pytest.MonkeyPatch) -> None:
    from cve_inventory import processing
    from cve_inventory.validation import InvalidInventory

    receipt, _ = await submit(browser)

    async def invalid(*_args: Any, **_kwargs: Any) -> Any:
        raise InvalidInventory("invalid_contract")

    monkeypatch.setattr(processing, "prepare", invalid)
    await drain(browser)
    with browser.lab.owner() as c:
        state = c.execute(
            "SELECT * FROM inventory.processing_status WHERE submission_id=%s",
            (receipt["submission_id"],),
        ).fetchone()
        assert state["status"] == "rejected_after_acceptance"
        assert state["attempts"] == 1 and state["job_status"] == "succeeded"


@pytest.mark.asyncio
async def test_runtime_container_recovery_and_isolation(browser: Browser) -> None:
    from scripts.infrastructure.manage import compose, docker_command, run
    from scripts.inventory_processor import manage

    cfg = browser.lab.config
    receipt, _ = await submit(browser)
    await asyncio.to_thread(manage.build, cfg)
    manage.prepare(cfg)
    try:
        await asyncio.to_thread(
            compose, cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-inventory"]
        )
        import hashlib
        import inspect

        from cve_inventory import normalization, processing, validation

        expected_sources = [
            hashlib.sha256(inspect.getsource(module).encode()).hexdigest()
            for module in (processing, validation, normalization)
        ]
        image_sources = compose(
            cfg,
            [
                "exec",
                "-T",
                "cve-inventory",
                "python",
                "-c",
                "import hashlib,inspect,json; from cve_inventory import "
                "processing,validation,normalization; print(json.dumps(["
                "hashlib.sha256(inspect.getsource(m).encode()).hexdigest() "
                "for m in (processing,validation,normalization)]))",
            ],
        )
        assert json.loads(image_sources.stdout) == expected_sources

        def probe(path: str) -> int:
            result = compose(
                cfg,
                [
                    "exec",
                    "-T",
                    "cve-inventory",
                    "python",
                    "-c",
                    "import urllib.request,urllib.error; "
                    "\ntry: print(urllib.request.urlopen('http://127.0.0.1:8000/"
                    + path
                    + "',timeout=2).status)"
                    "\nexcept urllib.error.HTTPError as e: print(e.code)",
                ],
            )
            return int(result.stdout.strip())

        assert await asyncio.to_thread(probe, "health/ready") == 200
        with browser.lab.owner() as diagnostic:
            state = diagnostic.execute(
                "SELECT * FROM inventory.processing_status WHERE submission_id=%s",
                (receipt["submission_id"],),
            ).fetchone()
            assert state["status"] == "completed", {
                k: state[k] for k in ("status", "error_code", "job_status", "attempts")
            }
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT status FROM inventory.processing_status WHERE submission_id=%s",
                    (receipt["submission_id"],),
                ).fetchone()["status"]
                == "completed"
            )
        identity = compose(cfg, ["ps", "-q", "cve-inventory"]).stdout.strip()
        info = json.loads(run([*docker_command(), "inspect", identity]).stdout)[0]
        assert not info["HostConfig"]["PortBindings"]
        assert info["HostConfig"]["ReadonlyRootfs"]
        assert not info["HostConfig"]["Privileged"]
        assert set(info["NetworkSettings"]["Networks"]) == {cfg.project + "_cve_data"}
        assert all(
            not m.get("RW") and "docker.sock" not in m["Source"]
            for m in info["Mounts"]
            if m["Type"] == "bind"
        )
        network = compose(
            cfg,
            [
                "exec",
                "-T",
                "cve-inventory",
                "python",
                "-c",
                "import socket; s=socket.socket(); s.settimeout(.5)"
                "\ntry: s.connect(('1.1.1.1',443)); print('open')"
                "\nexcept OSError: print('blocked')",
            ],
        )
        assert network.stdout.strip() == "blocked"
        await asyncio.to_thread(compose, cfg, ["stop", "cve-postgres"])
        assert await asyncio.to_thread(probe, "health/live") == 200
        for _ in range(30):
            if await asyncio.to_thread(probe, "health/ready") == 503:
                break
            await asyncio.sleep(0.2)
        else:
            pytest.fail("Processor readiness did not detect database outage")
        await asyncio.to_thread(
            compose, cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"]
        )
        for _ in range(40):
            if await asyncio.to_thread(probe, "health/ready") == 200:
                break
            await asyncio.sleep(0.2)
        else:
            pytest.fail("Processor did not recover after database restart")
        # A real process kill and container restart retain the completed result.
        await asyncio.to_thread(compose, cfg, ["kill", "-s", "SIGKILL", "cve-inventory"])
        await asyncio.to_thread(
            compose, cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-inventory"]
        )
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT count(*) AS n FROM inventory.snapshots WHERE submission_id=%s",
                    (receipt["submission_id"],),
                ).fetchone()["n"]
                == 1
            )
    finally:
        await asyncio.to_thread(
            compose, cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"]
        )
        await asyncio.to_thread(compose, cfg, ["stop", "cve-inventory"])


@pytest.mark.asyncio
async def test_both_sources_share_one_snapshot_and_preserve_receipt(browser: Browser) -> None:
    from tests.inventory_upload.integration.conftest import dashboard
    from tests.inventory_upload.integration.test_acceptance import uploader

    upload = await provision(browser)
    person = await uploader(browser, upload.server["id"])
    value = sample()
    value["server_id"] = upload.server["id"]
    raw = json.dumps(value).encode()
    a = await technical(browser, upload, raw)
    b = await dashboard(browser, person, upload.server["id"], raw)
    assert a.status_code == b.status_code == 202
    await drain(browser, 2)
    with browser.lab.owner() as c:
        records = c.execute(
            "SELECT s.source,p.snapshot_id,p.status,s.payload_raw FROM "
            "inventory.submissions s JOIN inventory.submission_processing p "
            "ON p.submission_id=s.id WHERE s.inventory_id=%s",
            (value["inventory_id"],),
        ).fetchall()
        assert len(records) == 2 and len({r["snapshot_id"] for r in records}) == 1
        assert {r["source"] for r in records} == {"ansible_api", "dashboard_file"}
        assert all(r["payload_raw"] == raw and r["status"] == "completed" for r in records)
    status = await browser.client.get(
        b.json()["status_url"], headers={"cookie": "__Host-cve-session=" + person.cookie}
    )
    assert status.status_code == 200 and status.json()["status"] == "accepted"


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["partial", "failed"])
async def test_no_complete_current_from_incomplete_collection(browser: Browser, state: str) -> None:
    value = sample()
    value["collection_status"] = state
    value["packages"] = {"status": "failed", "error_code": "collect_failed"}
    if state == "failed":
        for field in ("os", "services", "containers", "images"):
            value[field] = {"status": "failed", "error_code": "collect_failed"}
    receipt, _ = await submit(browser, value)
    await drain(browser)
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT status FROM inventory.processing_status WHERE submission_id=%s",
                (receipt["submission_id"],),
            ).fetchone()["status"]
            == "completed"
        )
        assert (
            c.execute(
                "SELECT snapshot_id FROM inventory.server_current_snapshots WHERE server_id=%s",
                (receipt["server_id"],),
            ).fetchone()
            is None
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    [
        "UPDATE inventory.servers SET display_name='denied' WHERE false",
        "DELETE FROM inventory.server_group_memberships WHERE false",
        "UPDATE security.user_server_access SET can_read=false WHERE false",
    ],
)
async def test_native_write_denied(browser: Browser, operation: str) -> None:
    import psycopg

    from scripts.database import manage as db

    with (
        db.connect(browser.lab.config, "inventory_processor") as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute(operation)


@pytest.mark.asyncio
async def test_populated_snapshot_backup_restore(browser: Browser, tmp_path: Any) -> None:
    from scripts.database import manage as db

    receipt, _ = await submit(browser)
    await drain(browser)
    with browser.lab.owner() as c:
        state = c.execute(
            "SELECT status FROM inventory.processing_status WHERE submission_id=%s",
            (receipt["submission_id"],),
        ).fetchone()
        assert state["status"] == "completed"
    target = tmp_path / "populated-processor-backup"
    await asyncio.to_thread(db.backup, browser.lab.config, target)
    await asyncio.to_thread(db.restore_test, browser.lab.config, target)


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign_server", [False, True])
async def test_legacy_identity_collision_rejected(browser: Browser, foreign_server: bool) -> None:
    from uuid import UUID

    from tests.database.helpers import server, snapshot

    upload = await provision(browser)
    value = sample()
    value["server_id"] = upload.server["id"]
    with browser.lab.owner() as c:
        target = server(c) if foreign_server else UUID(upload.server["id"])
        old = snapshot(c, target, inventory_id=UUID(value["inventory_id"]))
        original = c.execute(
            "SELECT original_bytes FROM inventory.snapshots WHERE id=%s", (old,)
        ).fetchone()
    response = await technical(browser, upload, json.dumps(value).encode())
    assert response.status_code == 202
    await drain(browser)
    with browser.lab.owner() as c:
        state = c.execute(
            "SELECT * FROM inventory.processing_status WHERE submission_id=%s",
            (response.json()["submission_id"],),
        ).fetchone()
        assert state["status"] == "rejected_after_acceptance"
        assert state["error_code"] == "existing_inventory_conflict"
        assert state["snapshot_id"] is None and state["job_status"] == "succeeded"
        import psycopg

        with pytest.raises(psycopg.errors.CheckViolation), c.transaction():
            c.execute(
                "UPDATE inventory.submission_processing SET "
                "status='completed',snapshot_id=%s WHERE submission_id=%s",
                (old, response.json()["submission_id"]),
            )
        assert (
            c.execute(
                "SELECT original_bytes FROM inventory.snapshots WHERE id=%s", (old,)
            ).fetchone()
            == original
        )
        assert (
            c.execute(
                "SELECT snapshot_id FROM inventory.server_current_snapshots WHERE server_id=%s",
                (upload.server["id"],),
            ).fetchone()
            is None
        )


@pytest.mark.asyncio
async def test_acceptance_metrics_reflect_processing(browser: Browser) -> None:
    from scripts.database import manage as db

    receipt, _ = await submit(browser)
    await drain(browser)
    with browser.lab.owner() as c:
        c.execute("SELECT id FROM inventory.submissions WHERE id=%s", (receipt["submission_id"],))
        pending = c.execute(
            "SELECT count(*) AS n FROM inventory.processing_status WHERE "
            "status IN ('accepted','processing')"
        ).fetchone()["n"]
    with db.connect(browser.lab.config, "api_ingest") as c:
        metrics = required_row(c.execute("SELECT security.inventory_metrics() AS value"))["value"]
        assert metrics["pending_count"] == pending
    with db.connect(browser.lab.config, "inventory_processor") as c:
        assert (
            required_row(c.execute("SELECT inventory.processor_metrics() AS value"))["value"][
                "completed"
            ]
            > 0
        )


@pytest.mark.asyncio
async def test_current_pointer_precedes_unvalidated_legacy_view(browser: Browser) -> None:
    from uuid import UUID

    from tests.database.helpers import processed, snapshot

    receipt, _ = await submit(browser)
    with browser.lab.owner() as c:
        old = snapshot(c, UUID(receipt["server_id"]), captured="2099-01-01T00:00:00Z")
        processed(c, old)
    await drain(browser)
    with browser.lab.owner() as c:
        pointer = c.execute(
            "SELECT snapshot_id FROM inventory.server_current_snapshots WHERE server_id=%s",
            (receipt["server_id"],),
        ).fetchone()["snapshot_id"]
        assert pointer != old
        assert (
            c.execute(
                "SELECT id FROM inventory.current_snapshots WHERE server_id=%s",
                (receipt["server_id"],),
            ).fetchone()["id"]
            == pointer
        )
