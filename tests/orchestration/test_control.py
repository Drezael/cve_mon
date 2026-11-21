"""Real least-privilege jobs cannot cross stage boundaries without n8n receipts."""

from collections.abc import Iterator
from typing import cast
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from scripts.database import manage as db
from tests.cve_importer.conftest import Lab

pytestmark = pytest.mark.orchestration


@pytest.fixture
def control(import_lab: Lab) -> Iterator[Lab]:
    with import_lab.owner() as s:
        s.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
    yield import_lab
    with import_lab.owner() as s:
        s.execute("UPDATE automation.workflow_settings SET enabled=false")


def enqueue(lab: Lab, role: str, kind: str, correlation: UUID, *, scope: str = "test") -> UUID:
    payload = (
        {"run_id": str(uuid4())}
        if kind.startswith("cve.import.")
        else {"revisions": [str(uuid4())]}
    )
    with db.connect(lab.config, role) as s:
        row = s.execute(
            "SELECT id FROM automation.enqueue_job(%s,1,%s,%s,%s,0,NULL,NULL,3,%s,false)",
            (kind, Jsonb(payload), str(uuid4()), correlation, scope),
        ).fetchone()
        assert row
        return cast(UUID, row["id"])


def dispatch(lab: Lab, stage: str, execution: str = "fixture-1") -> dict[str, object]:
    with db.connect(lab.config, "workflow_control") as s:
        row = s.execute(
            "SELECT automation.workflow_dispatch(%s,%s,%s) value",
            (stage, execution, "cve-control-" + stage),
        ).fetchone()
        assert row
        return cast(dict[str, object], row["value"])


def status(lab: Lab, job: UUID) -> str:
    with lab.owner() as s:
        row = s.execute("SELECT status FROM automation.jobs WHERE id=%s", (job,)).fetchone()
        assert row
        return str(row["status"])


def test_pending_stage_is_unclaimable_until_n8n_authorizes(control: Lab) -> None:
    job = enqueue(control, "api_security", "cve.import.cve_list", uuid4())
    assert status(control, job) == "pending"
    with db.connect(control.config, "importer") as s:
        assert not s.execute(
            "SELECT * FROM automation.claim_job(ARRAY['cve.import.cve_list'],%s,30)", (uuid4(),)
        ).fetchone()
    with (
        db.connect(control.config, "api_security") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("SELECT automation.control_job(%s,'release')", (job,))
    assert dispatch(control, "import")["released"] == 1
    assert status(control, job) == "queued"
    assert dispatch(control, "import", "fixture-repeat")["released"] == 0
    with control.owner() as s:
        receipt = s.execute(
            "SELECT execution_id,workflow_id FROM automation.workflow_requests WHERE job_id=%s",
            (job,),
        ).fetchone()
        assert receipt == {"execution_id": "fixture-1", "workflow_id": "cve-control-import"}
        s.execute(
            "UPDATE automation.jobs SET status='cancelled',finished_at=clock_timestamp() "
            "WHERE id=%s",
            (job,),
        )


def test_index_to_matching_needs_a_new_stage_receipt(control: Lab) -> None:
    correlation = uuid4()
    index = enqueue(control, "importer", "matching.index_v5_batch", correlation)
    assert status(control, index) == "pending"
    dispatch(control, "index")
    child = enqueue(
        control, "matcher", "matching.index_v5_batch", correlation, scope="matching-internal"
    )
    assert status(control, child) == "pending"
    dispatch(control, "index")
    assert status(control, child) == "queued"
    evaluation = enqueue(
        control, "matcher", "matching.evaluate_v5_batch", correlation, scope="matching"
    )
    assert status(control, evaluation) == "pending"
    dispatch(control, "matching")
    assert status(control, evaluation) == "queued"
    # A second package cannot inherit the first package's next-stage authorization.
    second = enqueue(
        control, "matcher", "matching.evaluate_v5_batch", correlation, scope="matching"
    )
    assert status(control, second) == "pending"
    pagination = enqueue(
        control, "matcher", "matching.evaluate_v5_batch", correlation, scope="matching-internal"
    )
    assert status(control, pagination) == "pending"
    dispatch(control, "matching")
    assert status(control, pagination) == "queued"


def test_control_identity_has_no_domain_write_and_rejects_wrong_workflow(control: Lab) -> None:
    with (
        db.connect(control.config, "workflow_control") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("INSERT INTO cve.sources(id,name,enabled) VALUES('fixture','fixture',true)")
    with (
        db.connect(control.config, "workflow_control") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("SELECT automation.workflow_dispatch('import','fixture','cve-control-matching')")
    with (
        db.connect(control.config, "api_security") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("SELECT automation.workflow_dispatch('import','fixture','cve-control-import')")


def test_pause_resume_blocks_stage_and_technical_children(control: Lab) -> None:
    correlation = uuid4()
    job = enqueue(control, "importer", "matching.index_v5_batch", correlation)
    with db.connect(control.config, "api_security") as s:
        row = s.execute(
            "SELECT automation.workflow_run_control(%s,'pause') value", (correlation,)
        ).fetchone()
        assert row and row["value"]
    dispatch(control, "index")
    assert status(control, job) == "pending"
    with db.connect(control.config, "api_security") as s:
        s.execute("SELECT automation.workflow_run_control(%s,'resume')", (correlation,))
    dispatch(control, "index")
    assert status(control, job) == "queued"


def test_duplicate_ticks_reuse_request_without_creating_feedback(control: Lab) -> None:
    with db.connect(control.config, "workflow_control") as s:
        for _ in range(3):
            s.execute("SELECT automation.workflow_tick('status','fixture','cve-control-status')")
    with control.owner() as s:
        before = s.execute("SELECT count(*) AS n FROM automation.workflow_runs").fetchone()
    dispatch(control, "status")
    with db.connect(control.config, "workflow_control") as s:
        s.execute("SELECT automation.workflow_tick('status','fixture','cve-control-status')")
    with control.owner() as s:
        assert s.execute("SELECT count(*) AS n FROM automation.workflow_runs").fetchone() == before
        assert not s.execute(
            "SELECT 1 FROM automation.workflow_requests w JOIN automation.jobs j ON j.id=w.job_id "
            "WHERE w.stage='status' AND w.execution_id IS NULL AND j.status='pending'"
        ).fetchone()


def test_cancelled_run_cannot_be_revived_by_pause_or_resume(control: Lab) -> None:
    correlation = uuid4()
    job = enqueue(control, "importer", "matching.index_v5_batch", correlation)
    with db.connect(control.config, "api_security") as s:
        assert s.execute(
            "SELECT automation.workflow_run_control(%s,'cancel') value", (correlation,)
        ).fetchone() == {"value": True}
        for action in ("pause", "resume"):
            assert s.execute(
                "SELECT automation.workflow_run_control(%s,%s) value", (correlation, action)
            ).fetchone() == {"value": False}
    dispatch(control, "index")
    assert status(control, job) == "cancelled"


def test_control_cannot_schedule_other_sources(control: Lab) -> None:
    with (
        db.connect(control.config, "workflow_control") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute(
            "SELECT cve.schedule_import('nvd','initial','{}'::jsonb,'forbidden',%s)", (uuid4(),)
        )


def test_due_v5_update_is_scheduled_once_by_n8n(control: Lab) -> None:
    from cve_importer.contracts import Configuration

    with control.owner() as s:
        s.execute(
            "UPDATE automation.workflow_settings SET auto_updates=true,source_config=%s,"
            "next_update_at=clock_timestamp()-interval '1 minute'",
            (Jsonb(Configuration().model_dump(mode="json")),),
        )
    with db.connect(control.config, "workflow_control") as s:
        first = s.execute(
            "SELECT automation.workflow_tick('import','fixture','cve-control-import') value"
        ).fetchone()
        second = s.execute(
            "SELECT automation.workflow_tick('import','fixture','cve-control-import') value"
        ).fetchone()
    assert first and first["value"]["scheduled"] is True
    assert second and second["value"]["scheduled"] is False
    with control.owner() as s:
        assert not s.execute(
            "SELECT 1 FROM cve.import_runs WHERE request_key LIKE 'scheduled-update:%'"
        ).fetchone()
    with db.connect(control.config, "workflow_control") as s:
        for _ in range(64):
            row = s.execute(
                "SELECT automation.n8n_claim('scheduled','cve-control-queue') v"
            ).fetchone()
            assert row is not None
            item = row["v"]
            assert item["kind"] != "empty"
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,'scheduled','cve-control-queue')",
                (item["id"], item["lease_token"], item["kind"]),
            )
            if item["kind"] == "command":
                break
    with control.owner() as s:
        run = s.execute(
            "SELECT r.source_id,r.mode,j.status FROM cve.import_runs r "
            "JOIN automation.jobs j ON j.id=r.job_id WHERE r.request_key LIKE 'scheduled-update:%'"
        ).fetchall()
    assert run == [{"source_id": "cve_list", "mode": "initial", "status": "pending"}]
    assert dispatch(control, "import")["released"] == 1


def test_fifo_head_and_expired_leases_cannot_be_overtaken(control: Lab) -> None:
    first = enqueue(control, "importer", "matching.index_v5_batch", uuid4())
    second = enqueue(control, "matcher", "matching.evaluate_v5_batch", uuid4())
    assert dispatch(control, "matching")["released"] == 0
    with db.connect(control.config, "workflow_control") as s:
        row = s.execute("SELECT automation.n8n_claim('old','cve-control-queue') v").fetchone()
        assert row
        old = row["v"]
    with control.owner() as s:
        s.execute(
            "UPDATE automation.n8n_queue SET "
            "lease_until=clock_timestamp()-interval '1 second' WHERE id=%s",
            (old["id"],),
        )
    with db.connect(control.config, "workflow_control") as s:
        row = s.execute("SELECT automation.n8n_claim('new','cve-control-queue') v").fetchone()
        assert row
        new = row["v"]
    assert old["id"] == new["id"] and old["lease_token"] != new["lease_token"]
    with (
        db.connect(control.config, "workflow_control") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute(
            "SELECT automation.n8n_decide(%s,%s,'task','old','cve-control-queue')",
            (old["id"], old["lease_token"]),
        )
    with db.connect(control.config, "workflow_control") as s:
        s.execute(
            "SELECT automation.n8n_decide(%s,%s,'task','new','cve-control-queue')",
            (new["id"], new["lease_token"]),
        )
    assert status(control, first) == "queued" and status(control, second) == "pending"
    assert dispatch(control, "matching")["released"] == 1


def test_retry_attempt_requires_another_n8n_receipt(control: Lab) -> None:
    identity = enqueue(control, "importer", "matching.index_v5_batch", uuid4())
    with control.owner() as s:
        s.execute("UPDATE automation.jobs SET priority=100 WHERE id=%s", (identity,))
    assert dispatch(control, "index")["released"] == 1
    worker = uuid4()
    with db.connect(control.config, "matcher") as s:
        job = s.execute(
            "SELECT * FROM automation.claim_job(ARRAY['matching.index_v5_batch'],%s,30)", (worker,)
        ).fetchone()
        assert job and job["id"] == identity
        finished = s.execute(
            "SELECT automation.finish_job(%s,%s,%s,%s,'retry','NETWORK') AS ok",
            (identity, worker, job["lease_token"], job["fencing_token"]),
        ).fetchone()
        assert finished and finished["ok"]
    assert status(control, identity) == "pending"
    with control.owner() as s:
        row = s.execute(
            "SELECT released_at FROM automation.workflow_requests WHERE job_id=%s", (identity,)
        ).fetchone()
        assert row is not None and row["released_at"] is None
        s.execute(
            "UPDATE automation.n8n_queue SET available_at=clock_timestamp() WHERE job_id=%s",
            (identity,),
        )
        s.execute(
            "UPDATE automation.jobs SET scheduled_at=clock_timestamp() WHERE id=%s", (identity,)
        )
    assert dispatch(control, "index")["released"] == 1
    with control.owner() as s:
        row = s.execute(
            "SELECT count(*) AS n FROM automation.n8n_queue WHERE kind='task' AND job_id=%s",
            (identity,),
        ).fetchone()
        assert row is not None and row["n"] == 2
    assert status(control, identity) == "queued"


def test_transport_components_publish_reference_only_results(control: Lab) -> None:
    correlation, event, notification, attempt = (uuid4() for _ in range(4))
    with control.owner() as s:
        s.execute(
            "INSERT INTO security.users(username,email,display_name) "
            "VALUES('transport-fixture','transport@example.test','Transport fixture')"
        )
        s.execute(
            "INSERT INTO automation.event_outbox(id,event_type,source,aggregate_type,"
            "aggregate_id,payload,idempotency_key,correlation_id) "
            "VALUES(%s,'security.changed','security-api','fixture',%s,'{}',%s,%s)",
            (event, str(event), str(event), correlation),
        )
        s.execute(
            "INSERT INTO automation.event_deliveries(event_id,destination,runtime_version) "
            "VALUES(%s,'fixture',1)",
            (event,),
        )
        s.execute(
            "UPDATE automation.event_deliveries SET status='delivered',attempts=1 "
            "WHERE event_id=%s",
            (event,),
        )
        s.execute(
            "INSERT INTO automation.notification_intents(id,recipient_user_id,rule_id,"
            "template_id,kind,status,reason,correlation_id) "
            "SELECT %s,u.id,r.id,t.id,'digest','ready','fixture',%s "
            "FROM security.users u CROSS JOIN automation.notification_rules r "
            "CROSS JOIN automation.notification_templates t WHERE t.name='digest' LIMIT 1",
            (notification, correlation),
        )
        s.execute(
            "INSERT INTO automation.notification_delivery_attempts(id,notification_id,attempt,"
            "fencing_token,worker_id,message_id) VALUES(%s,%s,1,1,%s,'<fixture@example.test>')",
            (attempt, notification, uuid4()),
        )
        s.execute(
            "INSERT INTO automation.notification_history(notification_id,version,new_status,"
            "reason,correlation_id) VALUES(%s,1,'ready','fixture',%s)",
            (notification, correlation),
        )
        s.execute(
            "INSERT INTO automation.notification_delivery_results(attempt_id,status,reason,"
            "smtp_code,relay_instance) VALUES(%s,'relay_accepted','fixture',250,'fixture')",
            (attempt,),
        )
        s.execute(
            "INSERT INTO automation.notification_transport_evidence(notification_id,evidence_id,"
            "relay_instance,message_id,status,source,reason) "
            "VALUES(%s,%s,'fixture','<fixture@example.test>','upstream_accepted','postfix','fixture')",
            (notification, str(uuid4())),
        )
        rows = s.execute(
            "SELECT message_type,event_id,notification_id,payload FROM automation.n8n_queue "
            "WHERE correlation_id=%s ORDER BY sequence",
            (correlation,),
        ).fetchall()
        assert [r["message_type"] for r in rows] == [
            "event.delivery",
            "notification.transport",
            "notification.evidence",
        ]
        assert rows[0]["event_id"] == event
        assert all(r["notification_id"] == notification for r in rows[1:])
        assert rows[1]["payload"] == {"status": "relay_accepted", "smtp_code": 250}
        assert rows[2]["payload"] == {"status": "upstream_accepted"}


def test_prepare_preserves_saved_schedule_and_disabled_targets(import_lab: Lab) -> None:
    import hashlib

    from scripts.notifications.manage import n8n_directory
    from scripts.workflows.manage import prepare

    prepare(import_lab.config)
    with import_lab.owner() as s:
        s.execute(
            "UPDATE automation.workflow_settings SET enabled=false,auto_updates=false,"
            "update_interval=43200"
        )
        s.execute(
            "UPDATE automation.delivery_targets SET enabled=false,retry_base=13,retry_cap=79 "
            "WHERE id='workflow-index'"
        )
        schedule = s.execute(
            "SELECT to_jsonb(t) AS value FROM automation.workflow_settings t"
        ).fetchone()
        target = s.execute(
            "SELECT to_jsonb(t) AS value FROM automation.delivery_targets t "
            "WHERE id='workflow-index'"
        ).fetchone()
        assert schedule and target and not target["value"]["enabled"]
    key = n8n_directory(import_lab.config) / "config/encryption.key"
    before = hashlib.sha256(key.read_bytes()).hexdigest()
    prepare(import_lab.config)
    assert hashlib.sha256(key.read_bytes()).hexdigest() == before
    with import_lab.owner() as s:
        assert (
            s.execute("SELECT to_jsonb(t) AS value FROM automation.workflow_settings t").fetchone()
            == schedule
        )
        assert (
            s.execute(
                "SELECT to_jsonb(t) AS value FROM automation.delivery_targets t "
                "WHERE id='workflow-index'"
            ).fetchone()
            == target
        )
