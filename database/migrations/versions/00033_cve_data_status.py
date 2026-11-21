"""Minimized source status and idempotent administrator-triggered feed updates."""

from alembic import op

revision = "00033_cve_data_status"
down_revision = "00032_optional_mfa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use reviewed data-preserving backup/restore")


DDL = r"""
INSERT INTO security.permissions(code,description,identity_type,administrative,reauthentication,delegable)
 VALUES('cve:update','Request CVE data update','human',true,false,false);
INSERT INTO security.role_permissions(role_id,permission_code)
 SELECT id,'cve:update' FROM security.roles WHERE code='admin';
INSERT INTO security.audit_actions(action,writer_role) VALUES('cve.data_update_requested','api_security');
CREATE TABLE cve.dashboard_update_requests (
 id uuid PRIMARY KEY,actor_id uuid NOT NULL REFERENCES security.users(id),
 result jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION cve.dashboard_data_status() RETURNS jsonb LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object(
 'cve_count',(SELECT count(*) FROM cve.enrichment_identities WHERE kind='cve' AND current_revision_id IS NOT NULL),
 'record_count',(SELECT count(*) FROM cve.source_records WHERE current_revision_id IS NOT NULL),
 'sources',(SELECT jsonb_agg(jsonb_build_object(
  'id',s.id,'name',s.name,'enabled',s.enabled,
  'record_count',(SELECT count(*) FROM cve.source_records r WHERE r.source_id=s.id AND current_revision_id IS NOT NULL),
  'last_success_at',(SELECT max(finished_at) FROM cve.import_runs r WHERE r.source_id=s.id AND status='completed'),
  'last_attempt_at',(SELECT max(created_at) FROM cve.import_runs r WHERE r.source_id=s.id),
  'status',coalesce((SELECT effective_status FROM cve.import_run_status r WHERE r.source_id=s.id ORDER BY created_at DESC,id DESC LIMIT 1),'never'),
  'updating',EXISTS(SELECT 1 FROM cve.import_run_status r WHERE r.source_id=s.id AND effective_status IN ('planned','running'))
 ) ORDER BY s.id) FROM cve.sources s),
 'epss',jsonb_build_object('id','epss','name','EPSS','enabled',true,
 'record_count',coalesce((SELECT r.row_count FROM cve.epss_current_dataset h JOIN cve.epss_import_runs r ON r.id=h.dataset_id),0),
 'last_success_at',(SELECT max(completed_at) FROM cve.epss_import_runs WHERE status='completed'),
 'last_attempt_at',(SELECT max(created_at) FROM automation.jobs WHERE job_type='cve.epss.sync_daily'),
 'status',coalesce((SELECT CASE status WHEN 'succeeded' THEN 'completed' ELSE status END FROM automation.jobs WHERE job_type='cve.epss.sync_daily' ORDER BY created_at DESC,id DESC LIMIT 1),'never'),
 'updating',EXISTS(SELECT 1 FROM automation.jobs WHERE job_type='cve.epss.sync_daily' AND status IN ('pending','queued','retry_pending','running'))));
$$;
CREATE FUNCTION cve.dashboard_request_update(p_key uuid,p_actor uuid,p_config jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE previous cve.dashboard_update_requests;src text;rid uuid;old cve.import_runs;
 mode text;result jsonb:='[]';j automation.jobs;
BEGIN
 IF session_user<>'api_security' OR p_key IS NULL OR p_actor IS NULL
 OR NOT system.safe_metadata(p_config) OR jsonb_typeof(p_config->'enabled')<>'array'
 THEN RAISE EXCEPTION 'invalid dashboard update' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(833001);
 SELECT * INTO previous FROM cve.dashboard_update_requests WHERE id=p_key;
 IF previous.id IS NOT NULL THEN
  IF previous.actor_id<>p_actor THEN RAISE EXCEPTION 'request conflict' USING ERRCODE='23505'; END IF;
  RETURN previous.result;
 END IF;
 FOR src IN SELECT s.id FROM cve.sources s WHERE s.enabled AND p_config->'enabled' ? s.id
 AND (s.id<>'osv' OR jsonb_array_length(p_config->'osv_ecosystems')>0) ORDER BY s.id LOOP
  PERFORM 1 FROM cve.source_leases WHERE source_id=src FOR UPDATE;
  SELECT b.* INTO old FROM cve.import_run_status r JOIN cve.import_runs b ON b.id=r.id WHERE r.source_id=src
   AND r.effective_status IN ('planned','running') ORDER BY r.created_at DESC LIMIT 1;
  IF old.id IS NOT NULL THEN rid:=old.id;
  ELSE
   mode:=CASE WHEN EXISTS(SELECT 1 FROM cve.import_runs WHERE source_id=src AND status='completed') THEN 'incremental' ELSE 'initial' END;
   rid:=cve.schedule_import(src,mode,jsonb_build_object('configuration',p_config),p_key::text,p_key);
  END IF;
  result:=result||jsonb_build_array(jsonb_build_object('source',src,'id',rid));
 END LOOP;
 SELECT * INTO j FROM automation.jobs WHERE job_type='cve.epss.sync_daily'
 AND status IN ('pending','queued','retry_pending','running') ORDER BY created_at DESC LIMIT 1;
 IF j.id IS NULL THEN
  SELECT * INTO j FROM automation.enqueue_job('cve.epss.sync_daily',1,'{}'::jsonb,
   'dashboard:'||p_key::text,p_key,0,NULL,NULL,3,'cve-data',false);
 END IF;
 result:=result||jsonb_build_array(jsonb_build_object('source','epss','id',j.id));
 INSERT INTO cve.dashboard_update_requests(id,actor_id,result) VALUES(p_key,p_actor,result);
 INSERT INTO security.audit_log(actor_user_id,action,object_type,object_id,outcome,auth_runtime)
 VALUES(p_actor,'cve.data_update_requested','cve_data',p_key::text,'success',true);
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION cve.dashboard_data_status(),cve.dashboard_request_update(uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cve.dashboard_data_status(),cve.dashboard_request_update(uuid,uuid,jsonb) TO api_security;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 IF strpos(definition,'00032_optional_mfa')=0 THEN RAISE EXCEPTION 'Unexpected sampler head'; END IF;
 EXECUTE replace(definition,'00032_optional_mfa','00033_cve_data_status');
END $$;
"""
