"""Explicit operator reset of CVE data/derived pipelines; preserve identities and inventories."""

import json
from typing import Any

import psycopg
from psycopg import sql

from scripts.database import manage as db
from scripts.infrastructure.manage import Config, docker_command, run

PRESERVED = {
    "cve.sources",
    "matching.rule_versions",
    "matching.inventory_keys",
    "findings.policy_versions",
    "findings.active_policy",
}
NOTIFICATION_RUNTIME = {
    "automation.notification_intents",
    "automation.notification_delivery_attempts",
    "automation.notification_delivery_results",
    "automation.notification_history",
    "automation.notification_transport_evidence",
    "automation.notification_workflow_runs",
    "automation.notification_exception_warnings",
}


def plan(connection: psycopg.Connection[dict[str, Any]]) -> list[str]:
    tables = {
        r["name"]
        for r in connection.execute("""
SELECT schemaname||'.'||tablename AS name FROM pg_tables
WHERE schemaname IN ('cve','matching','findings')
""")
    } - PRESERVED
    foreign = connection.execute("""
SELECT conrelid::regclass::text AS child,confrelid::regclass::text AS parent
FROM pg_constraint WHERE contype='f'
""").fetchall()
    while True:
        following = tables | {
            r["child"]
            for r in foreign
            if r["parent"] in tables
            and r["child"] != "automation.n8n_queue"
            # Reports are retained; only their affected notification link is detached below.
            and (r["child"], r["parent"])
            != ("automation.mail_reports", "automation.notification_intents")
        }
        if following == tables:
            break
        tables = following
    for table in tables:
        if table in PRESERVED or (
            not table.startswith(("cve.", "matching.", "findings."))
            and table not in NOTIFICATION_RUNTIME
        ):
            raise ValueError("Unexpected CVE reset dependency: " + table)
    return sorted(tables)


def reset_in(connection: psycopg.Connection[dict[str, Any]]) -> dict[str, Any]:
    """Caller owns transaction, quiescence and verified backup; no implicit commit or cascade."""
    tables = plan(connection)
    connection.execute("SET LOCAL statement_timeout='15min'")
    connection.execute("SELECT pg_advisory_xact_lock(833001)")
    connection.execute("""
CREATE TEMP TABLE reset_cve_events ON COMMIT DROP AS SELECT id FROM automation.event_outbox
WHERE event_type LIKE 'cve.%' OR event_type LIKE 'matching.%' OR event_type LIKE 'findings.%'
""")
    connection.execute("CREATE UNIQUE INDEX ON reset_cve_events(id)")
    connection.execute("ANALYZE reset_cve_events")
    connection.execute("""
CREATE TEMP TABLE reset_cve_jobs ON COMMIT DROP AS
WITH RECURSIVE seeds AS (
 SELECT id FROM automation.jobs WHERE job_type LIKE 'cve.%' OR job_type LIKE 'matching.%'
 OR job_type LIKE 'findings.%'
 UNION SELECT j.id FROM automation.jobs j JOIN reset_cve_events e ON e.id=CASE
 WHEN j.payload->>'event_id' ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}$'
 THEN (j.payload->>'event_id')::uuid ELSE NULL END
 WHERE j.job_type NOT LIKE 'cve.%' AND j.job_type NOT LIKE 'matching.%'
 AND j.job_type NOT LIKE 'findings.%' AND j.payload ? 'event_id'
), affected AS (
 SELECT id FROM seeds
 UNION SELECT j.id FROM automation.jobs j JOIN affected a ON j.replay_of=a.id
) SELECT id FROM affected
""")
    connection.execute("CREATE UNIQUE INDEX ON reset_cve_jobs(id)")
    counts = {}
    for name in ("reset_cve_events", "reset_cve_jobs"):
        row = connection.execute(
            sql.SQL("SELECT count(*) n FROM {}").format(sql.Identifier(name))
        ).fetchone()
        assert row is not None
        counts[name] = row["n"]
    # Refuse orphaning any unrelated job owner; CVE and derived tables are explicitly reset below.
    for row in connection.execute("""
SELECT conrelid::regclass::text AS child,a.attname AS column_name
FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=c.conkey[1]
WHERE c.contype='f' AND c.confrelid='automation.jobs'::regclass AND cardinality(c.conkey)=1
""").fetchall():
        if row["child"] in tables or row["child"] in {
            "automation.jobs",
            "automation.job_attempts",
            "automation.workflow_requests",
        }:
            continue
        schema, table = row["child"].split(".")
        exists = connection.execute(
            sql.SQL("SELECT 1 FROM {} WHERE {} IN (SELECT id FROM reset_cve_jobs) LIMIT 1").format(
                sql.Identifier(schema, table), sql.Identifier(row["column_name"])
            )
        ).fetchone()
        if exists:
            raise ValueError("Unrelated job reference in " + row["child"])
    connection.execute("""
CREATE TEMP TABLE reset_cve_notifications ON COMMIT DROP AS
WITH RECURSIVE affected AS (
 SELECT id,digest_id FROM automation.notification_intents WHERE finding_id IS NOT NULL
 OR event_id IN (SELECT id FROM reset_cve_events)
 UNION
 SELECT n.id,n.digest_id FROM automation.notification_intents n JOIN affected a ON n.id=a.digest_id
) SELECT DISTINCT id FROM affected
""")
    connection.execute("CREATE UNIQUE INDEX ON reset_cve_notifications(id)")
    connection.execute("""
CREATE TEMP TABLE reset_cve_attempts ON COMMIT DROP AS
SELECT id FROM automation.notification_delivery_attempts
WHERE notification_id IN (SELECT id FROM reset_cve_notifications)
""")
    # The shared n8n queue also owns SMTP/restart/recovery commands. A TRUNCATE
    # closure would erase those unrelated settings, so delete only reviewed CVE
    # runtime rows under the same explicit, quiescent operator transaction.
    connection.execute("SET LOCAL session_replication_role=replica")
    connection.execute("""
DELETE FROM automation.n8n_queue WHERE job_id IN (SELECT id FROM reset_cve_jobs)
 OR event_id IN (SELECT id FROM reset_cve_events)
 OR notification_id IN (SELECT id FROM reset_cve_notifications)
 OR (kind='command' AND message_type='cve.refresh')
""")
    connection.execute("""
UPDATE automation.mail_reports SET notification_id=NULL,state='cancelled',
 error_code='cve_data_reset'
WHERE notification_id IN (SELECT id FROM reset_cve_notifications)
""")
    for name in tables:
        query = sql.SQL("DELETE FROM {}").format(sql.Identifier(*name.split(".")))
        if name in NOTIFICATION_RUNTIME:
            if name == "automation.notification_exception_warnings":
                pass  # Every exception belongs to the findings being reset.
            elif name == "automation.notification_intents":
                query += sql.SQL(" WHERE id IN (SELECT id FROM reset_cve_notifications)")
            elif name == "automation.notification_delivery_results":
                query += sql.SQL(" WHERE attempt_id IN (SELECT id FROM reset_cve_attempts)")
            else:
                query += sql.SQL(
                    " WHERE notification_id IN (SELECT id FROM reset_cve_notifications)"
                )
        connection.execute(query)
    workflow_table = connection.execute(
        "SELECT to_regclass('automation.workflow_requests') AS name"
    ).fetchone()
    if workflow_table and workflow_table["name"]:
        connection.execute(
            "DELETE FROM automation.workflow_requests WHERE job_id IN (SELECT id FROM "
            "reset_cve_jobs)"
        )
        connection.execute(
            "DELETE FROM automation.workflow_runs r WHERE NOT EXISTS(SELECT 1 FROM "
            "automation.workflow_requests w WHERE w.correlation_id=r.correlation_id)"
        )
        connection.execute(
            "UPDATE automation.workflow_settings SET "
            "auto_updates=false,updated_at=clock_timestamp() WHERE singleton"
        )
    connection.execute(
        "DELETE FROM automation.delivery_attempts WHERE event_id IN "
        "(SELECT id FROM reset_cve_events)"
    )
    for row in connection.execute("""
SELECT conrelid::regclass::text AS child,a.attname AS column_name
FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=c.conkey[1]
WHERE c.contype='f' AND c.confrelid='automation.event_outbox'::regclass
AND cardinality(c.conkey)=1
""").fetchall():
        schema, table = row["child"].split(".")
        connection.execute(
            sql.SQL("DELETE FROM {} WHERE {} IN (SELECT id FROM reset_cve_events)").format(
                sql.Identifier(schema, table), sql.Identifier(row["column_name"])
            )
        )
    connection.execute(
        "DELETE FROM automation.event_outbox WHERE id IN (SELECT id FROM reset_cve_events)"
    )
    connection.execute(
        "DELETE FROM automation.job_attempts WHERE job_id IN (SELECT id FROM reset_cve_jobs)"
    )
    connection.execute("DELETE FROM automation.jobs WHERE id IN (SELECT id FROM reset_cve_jobs)")
    connection.execute(
        "DELETE FROM system.source_sync_state WHERE source_id IN (SELECT id FROM cve.sources)"
    )
    connection.execute("UPDATE cve.sources SET enabled=(id='cve_list')")
    connection.execute("DELETE FROM status.source_expectations WHERE source_id<>'cve_list'")
    connection.execute("DELETE FROM cve.sources WHERE id<>'cve_list'")
    connection.execute("INSERT INTO cve.source_leases(source_id) SELECT id FROM cve.sources")
    connection.execute("SET LOCAL session_replication_role=origin")
    connection.execute("""
INSERT INTO security.audit_log(action,object_type,outcome,metadata)
VALUES('cve.data_reset','cve_data','success',jsonb_build_object('source','cve_list','transport','git'))
""")
    return {"truncated_tables": tables, **counts, "preserved": sorted(PRESERVED)}


def reset(config: Config) -> dict[str, Any]:
    # In-flight work could resurrect cleared data; require a stopped application before reset.
    for service in ("cve-api", "cve-processing", "cve-sources", "cve-n8n"):
        active = run(
            [
                *docker_command(),
                "ps",
                "-q",
                "--filter",
                "label=com.docker.compose.project=" + config.project,
                "--filter",
                "label=com.docker.compose.service=" + service,
            ]
        ).stdout.strip()
        if active:
            raise ValueError("Stop application before CVE reset: " + service)
    with db.connect(config) as connection:
        return reset_in(connection)


def main() -> None:
    import argparse
    import hashlib
    from pathlib import Path

    from scripts.infrastructure.manage import load_config

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--encrypted-backup", type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads((args.encrypted_backup / "manifest.json").read_text())
    if not metadata.get("completed") or set(metadata.get("databases", {})) != set(db.DATABASES):
        raise ValueError("Completed backup of both databases required")
    for item in metadata["databases"].values():
        path = args.encrypted_backup / item["file"]
        with path.open("rb") as handle:
            if hashlib.file_digest(handle, "sha256").hexdigest() != item["sha256"]:
                raise ValueError("Encrypted backup checksum mismatch")
    print(json.dumps(reset(load_config()), sort_keys=True))


if __name__ == "__main__":
    main()
