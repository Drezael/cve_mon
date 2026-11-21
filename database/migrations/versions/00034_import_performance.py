"""Indexed bounded queue heads preserve aging, priority, ownership and skip-locked claims."""

from alembic import op

revision = "00034_import_performance"
down_revision = "00033_cve_data_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use reviewed data-preserving backup/restore")


DDL = r"""
CREATE INDEX jobs_runtime_priority ON automation.jobs(job_type,priority DESC,scheduled_at,id)
 WHERE runtime_version=1 AND status IN ('queued','retry_pending');
CREATE INDEX jobs_runtime_deadlines ON automation.jobs(deadline,id)
 WHERE runtime_version=1 AND status IN ('pending','queued','retry_pending') AND deadline IS NOT NULL;
CREATE OR REPLACE FUNCTION automation.claim_job(p_types text[],p_worker uuid,p_lease double precision) RETURNS SETOF automation.jobs
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j automation.jobs; ts timestamptz:=clock_timestamp(); seconds integer;
BEGIN
 IF p_worker IS NULL OR p_lease NOT BETWEEN 0.2 AND 300 OR cardinality(p_types) NOT BETWEEN 1 AND 32 THEN
 RAISE EXCEPTION 'invalid claim' USING ERRCODE='22023'; END IF;
 SELECT q.* INTO j FROM automation.job_types jt
 CROSS JOIN LATERAL (
  SELECT q.id,q.scheduled_at,q.priority FROM automation.jobs q
  WHERE q.job_type=jt.code AND q.runtime_version=1
   AND q.status IN ('queued','retry_pending') AND q.scheduled_at<ts-interval '60 seconds'
   AND q.attempts<q.max_attempts AND (q.deadline IS NULL OR q.deadline>ts)
  ORDER BY q.scheduled_at,q.priority DESC,q.id FOR UPDATE OF q SKIP LOCKED LIMIT 1
 ) candidate JOIN automation.jobs q ON q.id=candidate.id
 WHERE jt.code=ANY(p_types) AND jt.handler_role=session_user
 ORDER BY q.scheduled_at,q.priority DESC,q.id LIMIT 1;
 IF j.id IS NULL THEN
 SELECT q.* INTO j FROM automation.job_types jt
 CROSS JOIN LATERAL (
  SELECT q.id,q.scheduled_at,q.priority FROM automation.jobs q
  WHERE q.job_type=jt.code AND q.runtime_version=1
   AND q.status IN ('queued','retry_pending') AND q.scheduled_at>=ts-interval '60 seconds' AND q.scheduled_at<=ts
   AND q.attempts<q.max_attempts AND (q.deadline IS NULL OR q.deadline>ts)
  ORDER BY q.priority DESC,q.scheduled_at,q.id FOR UPDATE OF q SKIP LOCKED LIMIT 1
 ) candidate JOIN automation.jobs q ON q.id=candidate.id
 WHERE jt.code=ANY(p_types) AND jt.handler_role=session_user
 ORDER BY q.priority DESC,q.scheduled_at,q.id LIMIT 1;
 END IF;
 IF j.id IS NULL THEN RETURN; END IF;
 SELECT runtime_seconds INTO seconds FROM automation.job_types WHERE code=j.job_type;
 UPDATE automation.jobs SET status='running',attempts=attempts+1,fencing_token=fencing_token+1,
 lease_owner=p_worker,lease_token=gen_random_uuid(),execution_deadline=least(ts+make_interval(secs=>seconds),deadline),
 lease_until=least(ts+make_interval(secs=>p_lease),ts+make_interval(secs=>seconds),deadline),
 heartbeat_at=ts,started_at=ts,finished_at=NULL,error_code=NULL,updated_at=ts WHERE id=j.id RETURNING * INTO j;
 INSERT INTO automation.job_attempts(job_id,attempt,fencing_token,worker_id,lease_token,started_at)
 VALUES(j.id,j.attempts,j.fencing_token,p_worker,j.lease_token,ts);
 RETURN NEXT j;
END $$;
CREATE OR REPLACE FUNCTION cve.dashboard_request_update(p_key uuid,p_actor uuid,p_config jsonb) RETURNS jsonb
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
   -- Retry the leased failed import at its committed checkpoint, retaining its
   -- pinned configuration and upper timestamp. Never reuse a completed/partial run.
   SELECT r.* INTO old FROM cve.import_runs r JOIN cve.source_leases l ON l.active_run=r.id
    JOIN automation.jobs retry_job ON retry_job.id=r.job_id WHERE l.source_id=src
    AND r.status NOT IN ('completed','partial') AND r.progress<>'{}'::jsonb
    AND r.context=jsonb_build_object('configuration',p_config)
    AND retry_job.status IN ('failed','timed_out','cancelled');
   IF old.id IS NOT NULL THEN
    rid:=old.id;
    UPDATE cve.import_runs SET job_id=automation.control_job(old.job_id,'replay'),
     status='planned',finished_at=NULL WHERE id=rid;
   ELSE
   mode:=CASE WHEN EXISTS(SELECT 1 FROM cve.import_runs WHERE source_id=src AND status='completed') THEN 'incremental' ELSE 'initial' END;
   rid:=cve.schedule_import(src,mode,jsonb_build_object('configuration',p_config),p_key::text,p_key);
  END IF;
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
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 IF strpos(definition,'00033_cve_data_status')=0 THEN RAISE EXCEPTION 'Unexpected sampler head'; END IF;
 EXECUTE replace(definition,'00033_cve_data_status','00034_import_performance');
END $$;
"""
