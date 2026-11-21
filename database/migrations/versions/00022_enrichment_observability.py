"""Complete aggregate enrichment operations metrics without widening runtime reads."""

from alembic import op

revision = "00022_enrichment_observability"
down_revision = "00021_cve_enrichment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Data-preserving rollback requires reviewed backup/restore")


DDL = r"""
CREATE OR REPLACE FUNCTION cve.enricher_metrics() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
WITH jobs AS MATERIALIZED (
 SELECT * FROM automation.jobs WHERE job_type IN ('cve.enrich.record','cve.enrich.backfill','cve.enrich.reconcile','cve.epss.sync_daily')
), assessments AS MATERIALIZED (
 SELECT a.value,a.enrichment_revision_id FROM cve.enrichment_assertions a
 JOIN cve.enrichment_identities i ON i.current_revision_id=a.enrichment_revision_id WHERE a.category='cvss'
), versions AS (
 SELECT value->>'cvss_version' AS version,count(*) AS count FROM assessments
 WHERE value->>'validation_status'='valid' GROUP BY value->>'cvss_version'
), durations AS (
 SELECT j.job_type,a.duration_ms FROM jobs j JOIN automation.job_attempts a ON a.job_id=j.id WHERE a.finished_at IS NOT NULL
)
SELECT jsonb_build_object(
 'identities',(SELECT count(*) FROM cve.enrichment_identities),
 'revisions',(SELECT count(*) FROM cve.enrichment_revisions),
 'conflicts',(SELECT count(*) FROM cve.enrichment_assertions WHERE category='conflicts'),
 'queued',(SELECT count(*) FROM jobs WHERE status IN ('queued','pending','retry_pending')),
 'successful_enrichments',(SELECT count(*) FROM jobs WHERE job_type='cve.enrich.record' AND status='succeeded'),
 'failed_enrichments',(SELECT count(*) FROM jobs WHERE job_type='cve.enrich.record' AND status IN ('failed','timed_out')),
 'identities_with_valid_cvss',(SELECT count(DISTINCT enrichment_revision_id) FROM assessments WHERE value->>'validation_status'='valid'),
 'valid_cvss_fraction',(SELECT count(DISTINCT enrichment_revision_id)::numeric/NULLIF((SELECT count(*) FROM cve.enrichment_identities),0) FROM assessments WHERE value->>'validation_status'='valid'),
 'cvss_versions',COALESCE((SELECT jsonb_object_agg(version,count) FROM versions),'{}'::jsonb),
 'kev_age_hours',(SELECT extract(epoch FROM clock_timestamp()-last_success_at)/3600 FROM cve.source_streams WHERE source_id='cisa_kev' AND stream='main'),
 'current_epss',(SELECT jsonb_build_object('date',r.score_date,'model',r.model_version,'rows',r.row_count,'age_days',current_date-r.score_date) FROM cve.epss_current_dataset h JOIN cve.epss_import_runs r ON r.id=h.dataset_id),
 'epss_import_duration_ms',(SELECT avg(duration_ms) FROM durations WHERE job_type='cve.epss.sync_daily'),
 'enrichment_duration_ms',(SELECT avg(duration_ms) FROM durations WHERE job_type='cve.enrich.record'),
 'retry_count',(SELECT COALESCE(sum(greatest(attempts-1,0)),0) FROM jobs),
 'backfill_progress',jsonb_build_object(
  'completed_batches',(SELECT count(*) FROM jobs WHERE job_type IN ('cve.enrich.backfill','cve.enrich.reconcile') AND status='succeeded'),
  'pending_batches',(SELECT count(*) FROM jobs WHERE job_type IN ('cve.enrich.backfill','cve.enrich.reconcile') AND status IN ('queued','running','retry_pending'))),
 'active_workers',(SELECT count(DISTINCT lease_owner) FROM jobs WHERE status='running' AND lease_until>clock_timestamp()),
 'outbox_backlog',(SELECT count(*) FROM automation.event_deliveries d JOIN automation.event_outbox e ON e.id=d.event_id WHERE e.source='cve-enricher' AND d.status IN ('pending','running','retry_pending'))
)
$$;
GRANT EXECUTE ON FUNCTION cve.enricher_metrics() TO enricher,reporter,status_probe;
"""
