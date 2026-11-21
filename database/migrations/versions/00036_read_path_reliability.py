"""Bounded indexed monitoring reads under sustained imports; no domain-data rewrites."""

from contextlib import suppress

from alembic import op
from psycopg import Error

revision = "00036_read_path_reliability"
down_revision = "00035_pipeline_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    # Retain the migration lock across the required autocommit index builds.
    driver.execute("SELECT pg_advisory_lock(2026030301)")
    try:
        # Keep import and heartbeat writes available while indexes are built.
        with op.get_context().autocommit_block():
            for name, table, definition in INDEXES:
                existing = driver.execute(
                    "SELECT indisvalid,indrelid=%s::regclass FROM pg_index "
                    "WHERE indexrelid=to_regclass(%s)",
                    (table, name),
                ).fetchone()
                if existing and not existing[1]:
                    raise RuntimeError("Unexpected index relation")
                if existing and not existing[0]:
                    driver.execute("DROP INDEX CONCURRENTLY " + name, prepare=False)
                if not existing or not existing[0]:
                    driver.execute(definition, prepare=False)
        driver.execute("SELECT pg_advisory_xact_lock(2026030301)")
        driver.execute(DDL, prepare=False)
    finally:
        # On an aborted transaction the connection disposal releases the session lock.
        with suppress(Error):
            driver.execute("SELECT pg_advisory_unlock(2026030301)")


def downgrade() -> None:
    raise RuntimeError("Use reviewed data-preserving backup/restore")


INDEXES = [
    (
        "automation.jobs_monitoring_active",
        "automation.jobs",
        "CREATE INDEX CONCURRENTLY jobs_monitoring_active ON automation.jobs(scheduled_at,id)\n INCLUDE(job_type,status,heartbeat_at,lease_until)\n WHERE runtime_version=1 AND job_type<>'status.collect'\n AND status IN ('queued','retry_pending','running')",
    ),
    (
        "cve.source_records_count",
        "cve.source_records",
        "CREATE INDEX CONCURRENTLY source_records_count ON cve.source_records(source_id)\n WHERE current_revision_id IS NOT NULL",
    ),
    (
        "cve.enrichment_identities_count",
        "cve.enrichment_identities",
        "CREATE INDEX CONCURRENTLY enrichment_identities_count ON cve.enrichment_identities(kind)\n WHERE current_revision_id IS NOT NULL",
    ),
]


DDL = r"""
ALTER TABLE automation.jobs SET (
 autovacuum_vacuum_scale_factor=0.02,autovacuum_vacuum_threshold=1000,
 autovacuum_analyze_scale_factor=0.02,autovacuum_analyze_threshold=1000);
CREATE OR REPLACE FUNCTION cve.dashboard_data_status() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
 SET search_path=pg_catalog SET jit=off AS $$
 WITH records AS MATERIALIZED (
 SELECT source_id,count(*) AS n FROM cve.source_records
 WHERE current_revision_id IS NOT NULL GROUP BY source_id
 ), latest AS MATERIALIZED (
 SELECT DISTINCT ON (source_id) source_id,effective_status
 FROM cve.import_run_status ORDER BY source_id,
 CASE WHEN effective_status IN ('planned','running') THEN 0 ELSE 1 END,created_at DESC,id DESC
 )
 SELECT jsonb_build_object(
 'cve_count',(SELECT count(*) FROM cve.enrichment_identities WHERE kind='cve' AND current_revision_id IS NOT NULL),
 'record_count',(SELECT coalesce(sum(n),0)::bigint FROM records),
 'sources',(SELECT jsonb_agg(jsonb_build_object(
  'id',s.id,'name',s.name,'enabled',s.enabled,
  'record_count',coalesce((SELECT n FROM records WHERE source_id=s.id),0),
  'last_success_at',(SELECT max(finished_at) FROM cve.import_runs r WHERE r.source_id=s.id AND status='completed'),
  'last_attempt_at',(SELECT max(greatest(r.created_at,j.created_at)) FROM cve.import_runs r LEFT JOIN automation.jobs j ON j.id=r.job_id WHERE r.source_id=s.id),
  'status',coalesce((SELECT effective_status FROM latest WHERE source_id=s.id),'never'),
  'updating',EXISTS(SELECT 1 FROM cve.import_run_status r WHERE r.source_id=s.id AND effective_status IN ('planned','running'))
 ) ORDER BY s.id) FROM cve.sources s),
 'epss',jsonb_build_object('id','epss','name','EPSS','enabled',true,
 'record_count',coalesce((SELECT r.row_count FROM cve.epss_current_dataset h JOIN cve.epss_import_runs r ON r.id=h.dataset_id),0),
 'last_success_at',(SELECT max(completed_at) FROM cve.epss_import_runs WHERE status='completed'),
 'last_attempt_at',(SELECT max(created_at) FROM automation.jobs WHERE job_type='cve.epss.sync_daily'),
 'status',coalesce((SELECT CASE status WHEN 'succeeded' THEN 'completed' ELSE status END FROM automation.jobs WHERE job_type='cve.epss.sync_daily' ORDER BY created_at DESC,id DESC LIMIT 1),'never'),
 'updating',EXISTS(SELECT 1 FROM automation.jobs WHERE job_type='cve.epss.sync_daily' AND status IN ('pending','queued','retry_pending','running'))));
$$;

ALTER FUNCTION cve.dashboard_pipeline_status() SET jit=off;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 IF strpos(definition,'00035_pipeline_status')=0 THEN RAISE EXCEPTION 'Unexpected sampler head'; END IF;
 EXECUTE replace(definition,'00035_pipeline_status','00036_read_path_reliability');
END $$;
ALTER FUNCTION status.sample() SET jit=off;
"""
