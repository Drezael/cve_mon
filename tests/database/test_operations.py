"Migrationen, parallele Reservierungen, Persistenz und vollständiger Wiederaufbau."

import json
import shutil
import uuid
from pathlib import Path

import psycopg
import pytest
from sqlalchemy.exc import DBAPIError

from scripts.database.manage import (
    backup,
    connect,
    container_id,
    fingerprint,
    migrate,
    provision,
    restore_test,
    verify,
    workdir,
)
from scripts.infrastructure.manage import Config, compose, docker_command, run
from tests.database.helpers import (
    Connection,
    cve,
    finding,
    group,
    required_row,
    server,
    snapshot,
    user,
)

pytestmark = pytest.mark.database


def test_migration_repeat_provision_preserve_credentials(db_config: Config) -> None:
    before = fingerprint(db_config, "cve_monitoring")
    with connect(db_config, database="postgres") as connection:
        passwords = connection.execute(
            "SELECT rolname,sha256(rolpassword::bytea) AS digest FROM pg_authid "
            "WHERE rolpassword IS NOT NULL ORDER BY rolname"
        ).fetchall()
    provision(db_config)
    migrate(db_config)
    migrate(db_config)
    assert fingerprint(db_config, "cve_monitoring") == before
    with connect(db_config, database="postgres") as connection:
        assert (
            connection.execute(
                "SELECT rolname,sha256(rolpassword::bytea) AS digest FROM pg_authid "
                "WHERE rolpassword IS NOT NULL ORDER BY rolname"
            ).fetchall()
            == passwords
        )
        assert required_row(
            connection.execute(
                "SELECT bool_and(rolpassword LIKE 'SCRAM-SHA-256$%%') AS scram FROM "
                "pg_authid WHERE rolpassword IS NOT NULL"
            )
        )["scram"]


def test_failed_migration_rolls_back_all_ddl(db_config: Config, tmp_path: Path) -> None:
    location = tmp_path / "migrations"
    shutil.copytree(
        db_config.root / "database/migrations",
        location,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    head = verify(db_config)["head"]
    (location / "versions/failure_probe.py").write_text(
        'from alembic import op\nrevision="failure_probe"\ndown_revision='
        + repr(head)
        + (
            '\ndef upgrade():\n    op.execute("CREATE TABLE '
            'inventory.failure_probe(id int)")\n    op.execute("SELECT 1/0")\n'
        )
    )
    with pytest.raises(DBAPIError):
        migrate(db_config, script_location=location)
    with connect(db_config) as connection:
        assert (
            required_row(connection.execute("SELECT to_regclass('inventory.failure_probe') AS t"))[
                "t"
            ]
            is None
        )
    assert verify(db_config)["head"] == head


def test_job_skip_locked_and_stale_fencing(db_config: Config) -> None:
    ids = []
    with connect(db_config, "api_ingest") as connection:
        for _ in range(2):
            ids.append(
                required_row(
                    connection.execute(
                        (
                            "INSERT INTO automation.jobs(job_type,idempotency_key) VALUES "
                            "('inventory.process',%s) RETURNING id"
                        ),
                        (uuid.uuid4().hex,),
                    )
                )["id"]
            )
    claim = (
        "WITH next AS (SELECT id FROM automation.jobs WHERE id=ANY(%s) AND "
        "status='pending'\n      ORDER BY priority DESC,scheduled_at,id FOR "
        "UPDATE SKIP LOCKED LIMIT 1)\n      UPDATE automation.jobs j SET "
        "status='running',attempts=attempts+1,lease_owner=%s,\n      "
        "lease_until=now()+interval '120 "
        "seconds',fencing_token=fencing_token+1,started_at=now()\n      FROM "
        "next WHERE j.id=next.id RETURNING j.id,j.fencing_token"
    )
    one, two = (uuid.uuid4(), uuid.uuid4())
    with (
        connect(db_config, "inventory_processor") as first,
        connect(db_config, "inventory_processor") as second,
    ):
        a = required_row(first.execute(claim, (ids, one)))
        b = required_row(second.execute(claim, (ids, two)))
        assert a["id"] != b["id"] and a["fencing_token"] == b["fencing_token"] == 1
    with connect(db_config, "inventory_processor") as connection:
        connection.execute(
            ("UPDATE automation.jobs SET lease_until=now()-interval '1 second' WHERE id=%s"),
            (a["id"],),
        )
        connection.execute(
            (
                "UPDATE automation.jobs SET "
                "lease_owner=%s,lease_until=now()+interval '120 "
                "seconds',fencing_token=fencing_token+1,attempts=attempts+1 WHERE "
                "id=%s AND lease_until<now()"
            ),
            (two, a["id"]),
        )
        assert (
            connection.execute(
                (
                    "UPDATE automation.jobs SET "
                    "status='succeeded',lease_owner=NULL,lease_until=NULL WHERE id=%s "
                    "AND lease_owner=%s AND fencing_token=%s"
                ),
                (a["id"], one, a["fencing_token"]),
            ).rowcount
            == 0
        )
        assert (
            connection.execute(
                (
                    "UPDATE automation.jobs SET "
                    "status='succeeded',lease_owner=NULL,lease_until=NULL,finished_at=now"
                    "() WHERE id=%s AND lease_owner=%s AND fencing_token=%s"
                ),
                (a["id"], two, 2),
            ).rowcount
            == 1
        )
        connection.execute(
            (
                "INSERT INTO "
                "automation.job_attempts(job_id,attempt,fencing_token,worker_id,outco"
                "me,finished_at) VALUES (%s,2,2,%s,'succeeded',now())"
            ),
            (a["id"], two),
        )


def test_job_types_rls_and_forbidden_columns(db_config: Config) -> None:
    with (
        connect(db_config, "api_ingest") as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(
            ("INSERT INTO automation.jobs(job_type,idempotency_key) VALUES ('cve.import',%s)"),
            (uuid.uuid4().hex,),
        )
    with (
        connect(db_config, "api_ingest") as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(
            (
                "INSERT INTO automation.jobs(job_type,status,idempotency_key) VALUES "
                "('inventory.process','succeeded',%s)"
            ),
            (uuid.uuid4().hex,),
        )
    with connect(db_config, "importer") as connection:
        assert (
            required_row(
                connection.execute(
                    "SELECT count(*) AS n FROM automation.jobs WHERE job_type='inventory.process'"
                )
            )["n"]
            == 0
        )
        assert (
            connection.execute(
                "UPDATE automation.jobs SET status='failed' WHERE job_type='inventory.process'"
            ).rowcount
            == 0
        )


def test_outbox_atomic_rollback_and_duplicate(db_config: Config) -> None:
    key = uuid.uuid4().hex
    query = (
        "INSERT INTO "
        "automation.event_outbox(event_type,source,aggregate_type,aggregate_i"
        "d,payload,idempotency_key) VALUES "
        "('inventory.accepted','inventory-api','inventory',%s,'{}',%s) "
        "RETURNING id"
    )
    with connect(db_config, "api_ingest") as connection:
        identity = required_row(connection.execute(query, (key, key)))["id"]
        connection.rollback()
    with connect(db_config, "event_dispatcher") as connection:
        assert not connection.execute(
            "SELECT 1 FROM automation.event_outbox WHERE id=%s", (identity,)
        ).fetchone()
    with connect(db_config, "api_ingest") as connection:
        identity = required_row(connection.execute(query, (key, key)))["id"]
    with (
        connect(db_config, "api_ingest") as connection,
        pytest.raises(psycopg.errors.UniqueViolation),
    ):
        connection.execute(query, (key, key))
    with (
        connect(db_config, "event_dispatcher") as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(
            "UPDATE automation.event_outbox SET payload='{}' WHERE id=%s", (identity,)
        )
    with (
        connect(db_config, "api_ingest") as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(
            (
                "INSERT INTO "
                "automation.event_outbox(event_type,source,aggregate_type,aggregate_i"
                "d,payload,idempotency_key) VALUES "
                "('security.changed','security-api','user','x','{}',%s)"
            ),
            (uuid.uuid4().hex,),
        )


def test_parallel_outbox_delivery_claim(db_config: Config) -> None:
    ids = []
    with connect(db_config, "api_ingest") as connection:
        for _ in range(2):
            ids.append(
                required_row(
                    connection.execute(
                        (
                            "INSERT INTO "
                            "automation.event_outbox(event_type,source,aggregate_type,aggregate_i"
                            "d,payload,idempotency_key) VALUES "
                            "('inventory.accepted','inventory-api','snapshot','test','{}',%s) "
                            "RETURNING id"
                        ),
                        (uuid.uuid4().hex,),
                    )
                )["id"]
            )
    with connect(db_config, "event_dispatcher") as connection:
        for identity in ids:
            connection.execute(
                ("INSERT INTO automation.event_deliveries(event_id,destination) VALUES (%s,'n8n')"),
                (identity,),
            )
    query = (
        "SELECT event_id FROM automation.event_deliveries WHERE "
        "event_id=ANY(%s) AND status='pending' ORDER BY event_id FOR UPDATE "
        "SKIP LOCKED LIMIT 1"
    )
    with (
        connect(db_config, "event_dispatcher") as first,
        connect(db_config, "event_dispatcher") as second,
    ):
        a = required_row(first.execute(query, (ids,)))["event_id"]
        b = required_row(second.execute(query, (ids,)))["event_id"]
        assert a != b
        for connection, identity in ((first, a), (second, b)):
            connection.execute(
                (
                    "UPDATE automation.event_deliveries SET "
                    "status='running',lease_owner=%s,lease_until=now()+interval '120 "
                    "seconds',fencing_token=fencing_token+1,attempts=attempts+1 WHERE "
                    "event_id=%s"
                ),
                (uuid.uuid4(), identity),
            )


def test_concurrent_administration_and_duplicate_snapshot(db_config: Config) -> None:
    with connect(db_config, "api_security") as connection:
        grouping = group(connection)
    with connect(db_config, "dashboard_admin") as connection:
        target = server(connection)
    with connect(db_config, "api_security") as connection:
        connection.execute(
            "INSERT INTO inventory.server_group_memberships(server_id,group_id) VALUES (%s,%s)",
            (target, grouping),
        )
    with (
        connect(db_config, "dashboard_admin") as first,
        connect(db_config, "dashboard_admin") as second,
    ):
        first.execute("SELECT id FROM inventory.servers WHERE id=%s FOR UPDATE", (target,))
        second.execute("SET lock_timeout='150ms'")
        with pytest.raises(psycopg.errors.LockNotAvailable):
            second.execute(
                ("UPDATE inventory.servers SET description=%s,version=version+1 WHERE id=%s"),
                (str(grouping), target),
            )
        second.rollback()
        first.execute(
            ("UPDATE inventory.servers SET description=%s,version=version+1 WHERE id=%s"),
            (str(grouping), target),
        )
    identity = uuid.uuid4()
    with (
        connect(db_config, "inventory_processor") as first,
        connect(db_config, "inventory_processor") as second,
    ):
        snapshot(first, target, inventory_id=identity)
        second.execute("SET lock_timeout='150ms'")
        with pytest.raises(psycopg.errors.LockNotAvailable):
            snapshot(second, target, inventory_id=identity)
        second.rollback()
    with (
        connect(db_config, "inventory_processor") as connection,
        pytest.raises(psycopg.errors.UniqueViolation),
    ):
        snapshot(connection, target, inventory_id=identity)


def test_parallel_manual_sort_serialized_by_version(db_config: Config) -> None:
    with connect(db_config, "api_security") as connection:
        grouping = group(connection)
    with (
        connect(db_config, "api_security") as first,
        connect(db_config, "api_security") as second,
    ):
        assert (
            first.execute(
                "UPDATE inventory.server_groups SET version=2 WHERE id=%s AND version=1",
                (grouping,),
            ).rowcount
            == 1
        )
        second.execute("SET lock_timeout='150ms'")
        with pytest.raises(psycopg.errors.LockNotAvailable):
            second.execute(
                "UPDATE inventory.server_groups SET version=2 WHERE id=%s AND version=1",
                (grouping,),
            )
        second.rollback()
        first.commit()
        assert (
            second.execute(
                "UPDATE inventory.server_groups SET version=2 WHERE id=%s AND version=1",
                (grouping,),
            ).rowcount
            == 0
        )


def test_security_seed_roles_and_system_guard(db_config: Config) -> None:
    with connect(db_config, "api_security") as connection:
        assert {
            r["code"] for r in connection.execute("SELECT code FROM security.roles WHERE is_system")
        } == {"admin", "user_admin", "security_analyst", "viewer", "user"}
        assert (
            connection.execute(
                "UPDATE security.roles SET name='forged' WHERE code='admin'"
            ).rowcount
            == 0
        )
        assert (
            connection.execute(
                "DELETE FROM security.role_permissions WHERE role_id=(SELECT id FROM "
                "security.roles WHERE code='admin')"
            ).rowcount
            == 0
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("INSERT INTO security.permissions VALUES ('forged','forged')")
    with (
        connect(db_config, "api_security") as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(
            "INSERT INTO security.roles(code,name,is_system) VALUES ('forged','forged',true)"
        )


@pytest.mark.parametrize(
    "metadata",
    [
        {"token": "sensitive"},
        {"nested": {"password": None}},
        {"a": [{"totp_secret": None}]},
    ],
)
def test_audit_redaction_guard(db_config: Config, metadata: dict[str, object]) -> None:
    with (
        connect(db_config, "api_ingest") as connection,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        connection.execute(
            (
                "INSERT INTO security.audit_log(action,object_type,outcome,metadata) "
                "VALUES ('inventory.accepted','snapshot','success',%s)"
            ),
            (json.dumps(metadata),),
        )


def test_audit_source_allowlist_and_append_only(db_config: Config) -> None:
    with connect(db_config, "api_ingest") as connection:
        connection.execute(
            "INSERT INTO security.audit_log(action,object_type,outcome) VALUES "
            "('inventory.accepted','snapshot','success')"
        )
    with (
        connect(db_config, "api_ingest") as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(
            "INSERT INTO security.audit_log(action,object_type,outcome) VALUES "
            "('security.changed','user','success')"
        )
    with (
        connect(db_config, "api_security") as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute("DELETE FROM security.audit_log")


def test_snapshot_and_package_index_plans(owner: Connection) -> None:
    target = server(owner)
    owner.execute(
        (
            "WITH payloads AS (SELECT gen_random_uuid() AS "
            "identity,now()-i*interval '1 second' AS captured FROM "
            "generate_series(1,3000) i), originals AS (SELECT "
            "identity,captured,jsonb_build_object('inventory_id',identity,'server"
            "_id',%s::uuid,'schema_version','1.0','captured_at',captured,'collect"
            "ion_status','partial') AS document FROM payloads) INSERT INTO "
            "inventory.snapshots(inventory_id,server_id,schema_version,captured_a"
            "t,collection_status,content_sha256,original_json,original_bytes) "
            "SELECT "
            "identity,%s,'1.0',captured,'partial',sha256(convert_to(document::tex"
            "t,'UTF8')),document,convert_to(document::text,'UTF8') FROM originals"
        ),
        (target, target),
    )
    owner.execute("ANALYZE inventory.snapshots")
    plan = required_row(
        owner.execute(
            (
                "EXPLAIN (FORMAT JSON) SELECT * FROM inventory.snapshots WHERE "
                "server_id=%s ORDER BY captured_at DESC,inventory_id DESC LIMIT 1"
            ),
            (target,),
        )
    )["QUERY PLAN"]
    assert "snapshots_history" in json.dumps(plan)
    owner.execute("SET LOCAL enable_seqscan=off")
    plan = required_row(
        owner.execute(
            "EXPLAIN (FORMAT JSON) SELECT * FROM inventory.packages WHERE "
            "name='openssl' AND package_manager='dpkg' AND architecture='amd64'"
        )
    )["QUERY PLAN"]
    assert any(name in json.dumps(plan) for name in ("packages_software", "packages_version"))


def test_persistence_restart_recreate(db_config: Config) -> None:
    with connect(db_config, "api_security") as connection:
        grouping = group(connection)
    with connect(db_config, "dashboard_admin") as connection:
        target = server(connection)
    before = fingerprint(db_config, "cve_monitoring")
    original = container_id(db_config)
    compose(db_config, ["restart", "cve-postgres"])
    compose(db_config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
    assert fingerprint(db_config, "cve_monitoring") == before
    compose(
        db_config,
        ["up", "-d", "--force-recreate", "--wait", "--wait-timeout", "60", "cve-postgres"],
    )
    assert container_id(db_config) != original
    assert fingerprint(db_config, "cve_monitoring") == before
    with connect(db_config) as connection:
        assert connection.execute(
            "SELECT 1 FROM inventory.servers WHERE id=%s", (target,)
        ).fetchone()
        assert connection.execute(
            "SELECT 1 FROM inventory.server_groups WHERE id=%s", (grouping,)
        ).fetchone()


def test_full_backup_restore_without_source(db_config: Config) -> None:
    with connect(db_config) as connection:
        target = server(connection)
        person = user(connection)
        finding(connection, target)
        connection.execute(
            (
                "INSERT INTO dashboard.user_preferences(user_id,preferences) VALUES "
                '(%s,\'{"theme":"dark"}\')'
            ),
            (person,),
        )
        connection.execute(
            (
                "INSERT INTO "
                "security.sessions(user_id,verifier,csrf_verifier,auth_version,origin"
                ",expires_at,idle_expires_at) VALUES "
                "(%s,sha256('session-test'::bytea),sha256('csrf-test'::bytea),1,'http"
                "s://test.invalid',now()+interval '1 hour',now()+interval '20 "
                "minutes')"
            ),
            (person,),
        )
        connection.execute(
            (
                "INSERT INTO security.mfa_methods(user_id,kind,ciphertext,key_id) "
                "VALUES (%s,'totp',sha256('synthetic "
                "ciphertext'::bytea),'external-test-key')"
            ),
            (person,),
        )
        connection.execute(
            (
                "INSERT INTO security.recovery_codes(user_id,verifier) VALUES "
                "(%s,sha256('recovery-test'::bytea))"
            ),
            (person,),
        )
        connection.execute(
            (
                "INSERT INTO "
                "security.account_tokens(user_id,purpose,verifier,expires_at) VALUES "
                "(%s,'activation',sha256('activation-test'::bytea),now()+interval '1 "
                "hour')"
            ),
            (person,),
        )
        identifier, _ = cve(connection)
        connection.execute(
            (
                "INSERT INTO "
                "cve.enrichments(cve_id,source_id,source_revision,content_sha256,orig"
                "inal_json,observed_at) VALUES "
                "(%s,'ubuntu','restore',sha256('restore-test'::bytea),'{}',now())"
            ),
            (identifier,),
        )
    with connect(db_config, "n8n_app", "n8n") as connection:
        connection.execute(
            "CREATE TABLE public.restore_fixture(id int PRIMARY KEY, payload jsonb NOT NULL)"
        )
        connection.execute("INSERT INTO public.restore_fixture VALUES (1,'{\"synthetic\":true}')")
    directory = backup(db_config, workdir(db_config) / ("backup-test-" + uuid.uuid4().hex))
    assert all(p.stat().st_mode & 63 == 0 for p in directory.iterdir())
    assert "PASSWORD" not in (directory / "globals.sql").read_text().upper()
    compose(db_config, ["stop", "cve-postgres"])
    try:
        assert restore_test(db_config, directory)["schemas"] == 8
    finally:
        compose(db_config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
    (directory / "cve_monitoring.dump").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="Prüfsumme"):
        restore_test(db_config, directory)
    logs = run([*docker_command(), "logs", container_id(db_config)]).stderr
    assert "session-test" not in logs and "recovery-test" not in logs


def test_interrupted_migration_preserves_previous_head(db_config: Config, tmp_path: Path) -> None:
    "Ein tatsächlich abgebrochenes SQL-Statement lässt weder DDL noch neue Version zurück."
    import time
    from concurrent.futures import ThreadPoolExecutor

    location = tmp_path / "cancelled-migrations"
    shutil.copytree(
        db_config.root / "database/migrations",
        location,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    head = verify(db_config)["head"]
    (location / "versions/cancellation_probe.py").write_text(
        'from alembic import op\nrevision="cancellation_probe"\ndown_revision='
        + repr(head)
        + (
            '\ndef upgrade():\n    op.execute("CREATE TABLE '
            'inventory.cancel_probe(id int)")\n    op.execute("SELECT '
            'pg_sleep(30) /* phase3_cancel_probe */")\n'
        )
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(migrate, db_config, "head", location)
        with connect(db_config, autocommit=True) as connection:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                row = connection.execute(
                    "SELECT pid FROM pg_stat_activity WHERE usename='cve_migrator' AND "
                    "state='active' AND query LIKE '%%phase3_cancel_probe%%'"
                ).fetchone()
                if row:
                    assert required_row(
                        connection.execute(
                            "SELECT pg_cancel_backend(%s) AS cancelled", (row["pid"],)
                        )
                    )["cancelled"]
                    break
                time.sleep(0.05)
            else:
                pytest.fail("migration did not reach cancellation point")
        with pytest.raises(DBAPIError):
            future.result(timeout=10)
    assert verify(db_config)["head"] == head
    with connect(db_config) as connection:
        assert (
            required_row(connection.execute("SELECT to_regclass('inventory.cancel_probe') AS t"))[
                "t"
            ]
            is None
        )


def test_concurrent_membership_is_unique(db_config: Config) -> None:
    with connect(db_config, "api_security") as connection:
        grouping = group(connection)
    with connect(db_config, "dashboard_admin") as connection:
        target = server(connection)
    query = "INSERT INTO inventory.server_group_memberships(server_id,group_id) VALUES (%s,%s)"
    with (
        connect(db_config, "api_security") as first,
        connect(db_config, "api_security") as second,
    ):
        first.execute(query, (target, grouping))
        second.execute("SET lock_timeout='150ms'")
        with pytest.raises(psycopg.errors.LockNotAvailable):
            second.execute(query, (target, grouping))
        second.rollback()
        first.commit()
        with pytest.raises(psycopg.errors.UniqueViolation):
            second.execute(query, (target, grouping))
        second.rollback()
