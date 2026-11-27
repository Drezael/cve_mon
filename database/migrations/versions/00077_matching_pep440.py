"""Version PEP 440 matching and declare complete view/metric/status targets."""

from alembic import op

revision = "00077_matching_pep440"
down_revision = "00076_review_guards"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup rather than mislabel matching evidence")


DDL = r"""
CREATE OR REPLACE VIEW matching.current_evaluations AS
 SELECT c.current_version,r.*,
 (s.snapshot_id=r.snapshot_id AND e.current_revision_id=r.enrichment_revision_id
  AND a.status='active' AND r.rule_version='matching-3') AS is_current
 FROM matching.current_results c JOIN matching.result_revisions r ON r.id=c.result_id
 JOIN inventory.servers a ON a.id=r.server_id
 LEFT JOIN inventory.server_current_snapshots s ON s.server_id=r.server_id
 JOIN cve.enrichment_identities e ON e.identity=r.identity;
INSERT INTO matching.rule_versions VALUES
 ('matching-3','{"debian":"dpkg-1","rpm":"rpm-1","semver":"semver-2","pep440":"packaging-26.3"}',clock_timestamp());

CREATE OR REPLACE FUNCTION matching.metrics() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
SELECT jsonb_build_object(
 'queued',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status IN ('queued','retry_pending')),
 'completed',(SELECT count(*) FROM matching.runs WHERE rule_version='matching-3' AND status='succeeded'),
 'failed',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status IN ('failed','timed_out')),
 'candidates',(SELECT count(*) FROM matching.candidates),'results',(SELECT count(*) FROM matching.result_revisions),
 'statuses',(SELECT coalesce(jsonb_object_agg(status,n),'{}') FROM (SELECT status,count(*) n FROM matching.current_evaluations GROUP BY status) x),
 'conflicts',(SELECT count(*) FROM matching.result_conflicts),
 'unmapped',(SELECT coalesce(sum(unmapped_count),0) FROM matching.indexed_revisions),
 'stale',(SELECT count(*) FROM matching.current_evaluations WHERE NOT is_current),
 'retry_count',(SELECT coalesce(sum(greatest(attempts-1,0)),0) FROM automation.jobs WHERE job_type LIKE 'matching.%'),
 'duration_ms',(SELECT coalesce(sum(a.duration_ms),0) FROM automation.job_attempts a JOIN automation.jobs j ON j.id=a.job_id WHERE j.job_type LIKE 'matching.%'),
 'running',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status='running'),
 'successful_jobs',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status='succeeded'),
 'oldest_job_seconds',(SELECT extract(epoch FROM clock_timestamp()-min(created_at)) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status IN ('queued','retry_pending')),
 'current_changes',(SELECT count(*) FROM automation.event_outbox WHERE source='cve-matcher' AND event_type IN ('matching.created','matching.replaced')),
 'outbox_backlog',(SELECT count(*) FROM automation.event_deliveries d JOIN automation.event_outbox e ON e.id=d.event_id WHERE e.source='cve-matcher' AND d.status NOT IN ('delivered','cancelled')),
 'unevaluable_ranges',(SELECT count(*) FROM matching.component_results WHERE decision->>'reason' IN ('unsupported_comparator','git_graph_unavailable','invalid_range','unsupported_cna_range')),
 'coverage',(SELECT jsonb_build_object('evaluated',count(*),'globally_complete',count(*) FILTER(WHERE (value->>'global_negative')::boolean)) FROM matching.coverage),
 'active_workers',(SELECT count(DISTINCT lease_owner) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status='running'));
$$;
CREATE OR REPLACE FUNCTION status.sample() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT status.sample_v49() || jsonb_build_object('schema_ready',(SELECT version_num='00077_matching_pep440' FROM public.alembic_version),'source_auto_updates',cfg.auto_updates,
  'sources',coalesce((SELECT jsonb_agg(jsonb_build_object('id',s.id,
    'max_age_seconds',greatest(300,cfg.update_interval*2+300),
    'last_success',(SELECT finished_at FROM cve.import_runs r WHERE r.source_id=s.id AND r.status='completed' ORDER BY finished_at DESC LIMIT 1)))
   FROM cve.sources s WHERE s.enabled AND cfg.auto_updates AND cfg.source_config->'enabled' ? s.id),'[]'::jsonb))
 FROM automation.workflow_settings cfg WHERE singleton;
$$;
GRANT EXECUTE ON FUNCTION matching.metrics() TO matcher,reporter,status_probe;
REVOKE ALL ON FUNCTION status.sample() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION status.sample() TO status_probe;
"""
