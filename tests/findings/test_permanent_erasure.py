"""Erasure removes server-owned history and queued work while preserving another server."""

from uuid import uuid4

import pytest

from tests.authorization.integration.conftest import actor
from tests.findings.test_native import Harness, harness

__all__ = ["harness"]
pytestmark = pytest.mark.findings


async def test_permanent_server_erasure_removes_history_jobs_and_preserves_others(
    harness: Harness,
) -> None:
    first = await harness.create()
    other = await harness.create()
    admin = await actor(harness.browser)
    with harness.browser.lab.owner() as s:
        version = s.execute(
            "SELECT version FROM inventory.servers WHERE id=%s", (first["server_id"],)
        ).fetchone()["version"]
        s.execute(
            (
                "INSERT INTO inventory.ansible_profiles(server_id,owner_id,host,po"
                "rt,username,auth_method,key_id,ciphertext) VALUES(%s,%s,'10.1.2.3"
                "',22,'ansible','password','test',%s)"
            ),
            (first["server_id"], admin.id, b"ciphertext"),
        )
    digest, removed_notice, retained_notice = uuid4(), uuid4(), uuid4()
    with harness.browser.lab.owner() as s:
        for owned_finding in (first, other):
            s.execute(
                "INSERT INTO dashboard.ungrouped_server_order "
                "SELECT %s,coalesce(max(display_order),-1)+1 FROM dashboard.ungrouped_server_order "
                "ON CONFLICT(server_id) DO NOTHING",
                (owned_finding["server_id"],),
            )
        s.execute(
            "INSERT INTO dashboard.user_preferences(user_id,preferences) "
            "VALUES(%s,jsonb_build_object('filters',jsonb_build_array(%s::text,%s::text),"
            "'theme','dark')) ON CONFLICT(user_id) DO UPDATE SET "
            "preferences=excluded.preferences,version=dashboard.user_preferences.version+1",
            (admin.id, str(first["server_id"]), str(other["server_id"])),
        )
        rule = s.execute("SELECT id FROM automation.notification_rules LIMIT 1").fetchone()["id"]
        template = s.execute(
            "SELECT id FROM automation.notification_templates WHERE name='digest' LIMIT 1"
        ).fetchone()["id"]
        for notice, finding in ((digest, None), (removed_notice, first), (retained_notice, other)):
            event = (
                s.execute(
                    "SELECT id FROM automation.event_outbox WHERE aggregate_id=%s LIMIT 1",
                    (str(finding["id"]),),
                ).fetchone()
                if finding
                else None
            )
            s.execute(
                "INSERT INTO automation.notification_intents(id,event_id,finding_id,"
                "recipient_user_id,"
                "rule_id,template_id,kind,status,reason,correlation_id,digest_id) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,'deferred','fixture',%s,%s)",
                (
                    notice,
                    event["id"] if event else None,
                    finding["id"] if finding else None,
                    admin.id,
                    rule,
                    template,
                    "finding" if finding else "digest",
                    uuid4(),
                    digest if finding else None,
                ),
            )
            s.execute(
                "INSERT INTO automation.notification_history(notification_id,version,new_status,"
                "reason,correlation_id) VALUES(%s,1,'deferred','fixture',%s)",
                (notice, uuid4()),
            )
    response = await harness.browser.client.delete(
        "/api/v1/dashboard/servers/" + str(first["server_id"]),
        headers={"x-csrf-token": harness.browser.csrf, "if-match": '"' + str(version) + '"'},
    )
    assert response.status_code == 204, response.text
    with harness.browser.lab.owner() as s:
        for table in [
            "inventory.servers",
            "inventory.submissions",
            "inventory.snapshots",
            "matching.runs",
            "matching.result_revisions",
            "findings.findings",
            "inventory.ansible_profiles",
        ]:
            col = "id" if table == "inventory.servers" else "server_id"
            assert not s.execute(
                "SELECT 1 FROM " + table + " WHERE " + col + "=%s", (first["server_id"],)
            ).fetchone(), table
        assert s.execute("SELECT 1 FROM findings.findings WHERE id=%s", (other["id"],)).fetchone()
        assert not s.execute(
            "SELECT 1 FROM dashboard.ungrouped_server_order WHERE server_id=%s",
            (first["server_id"],),
        ).fetchone()
        assert s.execute(
            "SELECT 1 FROM dashboard.ungrouped_server_order WHERE server_id=%s",
            (other["server_id"],),
        ).fetchone()
        preferences = s.execute(
            "SELECT preferences FROM dashboard.user_preferences WHERE user_id=%s", (admin.id,)
        ).fetchone()["preferences"]
        assert preferences == {"filters": [str(other["server_id"])], "theme": "dark"}

        assert not s.execute(
            "SELECT 1 FROM automation.notification_intents WHERE id IN (%s,%s)",
            (digest, removed_notice),
        ).fetchone()
        retained = s.execute(
            "SELECT digest_id,status FROM automation.notification_intents WHERE id=%s",
            (retained_notice,),
        ).fetchone()
        assert retained and retained["digest_id"] is None and retained["status"] == "deferred"

        assert not s.execute(
            "SELECT 1 FROM automation.event_outbox WHERE strpos(payload::text,%s)>0",
            (str(first["server_id"]),),
        ).fetchone()
        assert not s.execute(
            "SELECT 1 FROM security.audit_log WHERE object_id=%s", (str(first["server_id"]),)
        ).fetchone()


async def test_host_erasure_clears_pending_ansible_and_managed_backup(harness: Harness) -> None:
    import asyncio
    import base64
    import shutil
    from uuid import uuid4

    from scripts.automation_executor.agent import erase, generation, register_backup

    finding = await harness.create()
    admin = await actor(harness.browser)
    config = harness.browser.lab.config
    folder = config.root / ".runtime" / ("server-erasure-test-" + uuid4().hex)
    folder.mkdir(mode=0o700)
    backup = folder / "backup"
    backup.mkdir(mode=0o700)
    (backup / "snapshot.enc").write_bytes(b"fixture-only")
    key = folder / "backup.key"
    key.write_bytes(base64.b64encode(b"x" * 32))
    key.chmod(0o600)
    register_backup(config, backup, key)
    with harness.browser.lab.owner() as session:
        version = session.execute(
            "SELECT version FROM inventory.servers WHERE id=%s", (finding["server_id"],)
        ).fetchone()["version"]
        session.execute(
            "INSERT INTO inventory.ansible_profiles(server_id,owner_id,host,port,username,"
            "auth_method,key_id,ciphertext) VALUES(%s,%s,'192.168.3.4',22,'collector',"
            "'password','test',%s)",
            (finding["server_id"], admin.id, b"fixture-only"),
        )
    path = "/api/v1/dashboard/servers/" + str(finding["server_id"]) + "/ansible/probe"
    response = await harness.browser.client.post(
        path, headers={"x-csrf-token": harness.browser.csrf}
    )
    assert response.status_code == 202, response.text
    before = generation(config)
    try:
        result = await asyncio.to_thread(
            erase,
            config,
            {
                "server_id": str(finding["server_id"]),
                "actor_id": str(admin.id),
                "version": version,
                "request_id": str(uuid4()),
            },
        )
        assert result["status"] == 204
        assert not backup.exists() and not key.exists()
        assert generation(config) == before + 1
        with harness.browser.lab.owner() as session:
            assert not session.execute(
                "SELECT 1 FROM inventory.ansible_runs WHERE server_id=%s", (finding["server_id"],)
            ).fetchone()
            assert not session.execute(
                "SELECT 1 FROM automation.jobs WHERE payload->>'run_id'=%s",
                (response.json()["run_id"],),
            ).fetchone()
        assert not list(
            (config.root / ".runtime/automation-executor" / config.project).glob("erase-*.json")
        )
    finally:
        shutil.rmtree(folder, ignore_errors=True)


async def test_large_unrelated_queue_does_not_block_api_during_erasure(harness: Harness) -> None:
    import asyncio
    import time

    from scripts.automation_executor.agent import erase
    from scripts.database import manage as db

    item = await harness.create()
    admin = await actor(harness.browser)
    config = harness.browser.lab.config
    with harness.browser.lab.owner() as session:
        version = session.execute(
            "SELECT version FROM inventory.servers WHERE id=%s", (item["server_id"],)
        ).fetchone()["version"]
        session.execute(
            "INSERT INTO automation.jobs(job_type,status,idempotency_key,payload,finished_at) "
            "SELECT 'status.collect','succeeded','unrelated-erasure-load:'||g,"
            "jsonb_build_object('reference',gen_random_uuid(),'padding',repeat('x',1500)),"
            "clock_timestamp() FROM generate_series(1,8000) g"
        )
        session.execute(
            "INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,correlation_id,"
            "deduplication_key,state,execution_id) SELECT 'event','status_probe','test.unrelated',"
            "jsonb_build_object('padding',repeat('x',1500)),gen_random_uuid(),"
            "'unrelated-erasure-history:'||g,'completed',(100000+g)::text "
            "FROM generate_series(1,8000) g"
        )
    started = time.monotonic()
    deletion = asyncio.create_task(
        asyncio.to_thread(
            erase,
            config,
            {
                "server_id": str(item["server_id"]),
                "actor_id": str(admin.id),
                "version": version,
                "request_id": str(uuid4()),
            },
        )
    )
    responses = []
    latencies = []
    try:
        while not deletion.done():
            reading = time.monotonic()
            response = await harness.browser.client.get("/api/v1/status/overview")
            latencies.append(time.monotonic() - reading)
            responses.append(response.status_code)
            await asyncio.sleep(0.05)
        result = await deletion
        assert result["status"] == 204
        assert len(responses) >= 2 and all(status == 200 for status in responses)
        assert max(latencies) < 1.2
        assert time.monotonic() - started < 8
        with db.connect(config) as session:
            remaining = session.execute(
                "SELECT count(*) n FROM automation.jobs "
                "WHERE idempotency_key LIKE 'unrelated-erasure-load:%%'"
            ).fetchone()
            assert remaining and remaining["n"] == 8000
            queue_remaining = session.execute(
                "SELECT count(*) n FROM automation.n8n_queue "
                "WHERE deduplication_key LIKE 'unrelated-erasure-history:%%'"
            ).fetchone()
            assert queue_remaining and queue_remaining["n"] == 8000

    finally:
        await asyncio.gather(deletion, return_exceptions=True)


async def test_slow_critical_erasure_aborts_without_blocking_login_and_is_not_retried(
    harness: Harness,
) -> None:
    import asyncio
    import json
    import time

    import psycopg

    from scripts.automation_executor.agent import abort_unfinished_erasures, directory, erase
    from scripts.database import manage as db

    item = await harness.create()
    admin = await actor(harness.browser)
    config = harness.browser.lab.config
    request_id = str(uuid4())
    with harness.browser.lab.owner() as session:
        definition = session.execute(
            "SELECT pg_get_functiondef('inventory.erase_server(uuid,uuid)'::regprocedure) d"
        ).fetchone()["d"]
        version = session.execute(
            "SELECT version FROM inventory.servers WHERE id=%s", (item["server_id"],)
        ).fetchone()["version"]
        delayed = definition.replace(
            "      IF NOT inventory.ansible_owner_active",
            "      PERFORM pg_sleep(1.5);\n      IF NOT inventory.ansible_owner_active",
        )
        assert delayed != definition
        session.execute(delayed)
    started = time.monotonic()
    task = asyncio.create_task(
        asyncio.to_thread(
            erase,
            config,
            {
                "server_id": str(item["server_id"]),
                "actor_id": str(admin.id),
                "version": version,
                "request_id": request_id,
            },
        )
    )
    latencies = []
    try:
        while not task.done():
            begin = time.monotonic()
            response = await harness.browser.client.get("/api/v1/auth/session")
            latencies.append(time.monotonic() - begin)
            assert response.status_code == 200
            await asyncio.sleep(0.05)
        with pytest.raises(psycopg.errors.TransactionTimeout):
            await task
        assert max(latencies) < 1.2 and time.monotonic() - started < 4
        path = directory(config) / ("erase-" + request_id + ".json")
        failure = json.loads(path.read_text())
        assert failure["phase"] == "failed" and failure["error_code"] == "CRITICAL_DEADLINE"
        assert failure["automatic_retry"] is False
        with db.connect(config) as session:
            assert session.execute(
                "SELECT 1 FROM inventory.servers WHERE id=%s", (item["server_id"],)
            ).fetchone()
            assert not session.execute(
                "SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=0 "
                "AND objid IN (7348001,909001) AND granted "
                "AND pid IN (SELECT pid FROM pg_stat_activity WHERE usename='dashboard_admin')"
            ).fetchone()
        abort_unfinished_erasures(config)
        assert (
            erase(
                config,
                {
                    "server_id": str(item["server_id"]),
                    "actor_id": str(admin.id),
                    "version": version,
                    "request_id": request_id,
                },
            )["status"]
            == 503
        )
    finally:
        await asyncio.gather(task, return_exceptions=True)
        with harness.browser.lab.owner() as session:
            session.execute(definition)
