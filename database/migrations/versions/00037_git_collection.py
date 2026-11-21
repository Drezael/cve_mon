"""Git-only collection controls and bounded batch enrichment jobs."""

from alembic import op

revision = "00037_git_collection"
down_revision = "00036_read_path_reliability"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use reviewed data-preserving backup/restore")


DDL = r"""
INSERT INTO automation.job_types(code,handler_role,producer_roles,runtime_seconds,max_attempts)
VALUES('cve.enrich.batch','enricher',ARRAY['api_security','enricher','importer']::name[],3600,3);
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('cve.source_enrichment_event()'::regprocedure) INTO definition;
 definition:=replace(definition,
 'IF NEW.source<>''cve-importer'' OR NEW.runtime_version<>1 THEN RETURN NEW;END IF;',
 'IF NEW.source<>''cve-importer'' OR NEW.runtime_version<>1 THEN RETURN NEW;END IF;
 IF NEW.payload->>''source_id''=''cve_list'' AND EXISTS(
 SELECT 1 FROM cve.import_runs r WHERE r.id=(NEW.payload->>''run_id'')::uuid
 AND coalesce(r.context->''configuration''->>''cve_list_transport'',''git'')=''git'')
 THEN RETURN NEW; END IF;');
 IF strpos(definition,'cve_list_transport')=0 THEN RAISE EXCEPTION 'Unexpected enrichment trigger'; END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('cve.dashboard_request_update(uuid,uuid,jsonb)'::regprocedure)
 INTO definition;
 definition:=replace(definition,
 'SELECT * INTO j FROM automation.jobs WHERE job_type=''cve.epss.sync_daily''',
 'IF coalesce((p_config->>''epss_enabled'')::boolean,false) THEN
 SELECT * INTO j FROM automation.jobs WHERE job_type=''cve.epss.sync_daily''');
 definition:=replace(definition,
 'INSERT INTO cve.dashboard_update_requests(id,actor_id,result)',
 'END IF; INSERT INTO cve.dashboard_update_requests(id,actor_id,result)');
 IF strpos(definition,'epss_enabled')=0 THEN RAISE EXCEPTION 'Unexpected dashboard refresh'; END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('cve.dashboard_pipeline_status()'::regprocedure) INTO definition;
 definition:=replace(definition,'''cve.enrich.record'',','''cve.enrich.batch'',''cve.enrich.record'',');
 EXECUTE definition;
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 IF strpos(definition,'00036_read_path_reliability')=0 THEN RAISE EXCEPTION 'Unexpected sampler head'; END IF;
 EXECUTE replace(definition,'00036_read_path_reliability','00037_git_collection');
END $$;
DROP INDEX automation.jobs_cve_pipeline_status;
CREATE INDEX jobs_cve_pipeline_status ON automation.jobs(job_type,status)
 WHERE runtime_version=1 AND job_type IN (
 'cve.enrich.batch','cve.enrich.record','cve.enrich.reconcile','cve.enrich.backfill','cve.epss.sync_daily');
ALTER FUNCTION cve.dashboard_pipeline_status() SET jit=off;
"""
