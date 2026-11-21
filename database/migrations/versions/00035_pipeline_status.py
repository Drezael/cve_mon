"""Read-only pipeline counts without per-job counter writes on the worker hot path."""

from alembic import op

revision = "00035_pipeline_status"
down_revision = "00034_import_performance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use reviewed data-preserving backup/restore")


DDL = r"""
CREATE INDEX jobs_cve_pipeline_status ON automation.jobs(job_type,status)
 WHERE runtime_version=1 AND job_type IN (
 'cve.enrich.record','cve.enrich.reconcile','cve.enrich.backfill','cve.epss.sync_daily');
CREATE FUNCTION cve.dashboard_pipeline_status() RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 WITH jobs AS (
 SELECT
 count(*) FILTER(WHERE status IN ('pending','queued')) AS waiting,
 count(*) FILTER(WHERE status='retry_pending') AS retrying,
 count(*) FILTER(WHERE status='running') AS running,
 count(*) FILTER(WHERE status='succeeded') AS completed_jobs,
 count(*) FILTER(WHERE status IN ('failed','timed_out')) AS failed_jobs
 FROM automation.jobs WHERE runtime_version=1 AND job_type IN (
 'cve.enrich.record','cve.enrich.reconcile','cve.enrich.backfill','cve.epss.sync_daily')
 ), identities AS (
 SELECT count(*) AS processed_records,
 count(*) FILTER(WHERE kind='cve') AS processed_cves,
 count(*) FILTER(WHERE kind='advisory') AS processed_advisories
 FROM cve.enrichment_identities WHERE current_revision_id IS NOT NULL
 )
 SELECT jsonb_build_object(
 'processed_records',i.processed_records,'processed_cves',i.processed_cves,
 'processed_advisories',i.processed_advisories,
 'waiting',j.waiting,'retrying',j.retrying,'running',j.running,
 'outstanding',j.waiting+j.retrying+j.running,
 'completed_jobs',j.completed_jobs,'failed_jobs',j.failed_jobs
 ) FROM jobs j CROSS JOIN identities i;
$$;
REVOKE ALL ON FUNCTION cve.dashboard_pipeline_status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cve.dashboard_pipeline_status() TO api_security;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 IF strpos(definition,'00034_import_performance')=0 THEN RAISE EXCEPTION 'Unexpected sampler head'; END IF;
 EXECUTE replace(definition,'00034_import_performance','00035_pipeline_status');
END $$;
"""
