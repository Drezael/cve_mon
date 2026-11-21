"""n8n authorizes application stages; PostgreSQL remains the fenced task executor."""

from alembic import op

revision = "00040_workflow_control"
down_revision = "00039_native_v5_json"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Restore the reviewed encrypted backup; never discard workflow receipts")


DDL = r"""
CREATE TABLE automation.workflow_settings (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),enabled boolean NOT NULL DEFAULT false,
 auto_updates boolean NOT NULL DEFAULT false,update_interval integer NOT NULL DEFAULT 1800
 CHECK(update_interval BETWEEN 300 AND 86400),next_update_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 source_config jsonb NOT NULL DEFAULT '{"enabled":["cve_list"],"cve_list_transport":"git","epss_enabled":false}'::jsonb,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO automation.workflow_settings(singleton) VALUES(true);
CREATE TABLE automation.workflow_runs (
 correlation_id uuid PRIMARY KEY,paused boolean NOT NULL DEFAULT false,cancelled boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE automation.workflow_requests (
 job_id uuid PRIMARY KEY REFERENCES automation.jobs(id),correlation_id uuid NOT NULL REFERENCES automation.workflow_runs(correlation_id),
 stage text NOT NULL CHECK(stage IN ('import','inventory','enrichment','index','matching','findings','notifications','status')),
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),execution_id text,workflow_id text,
 workflow_version integer,released_at timestamptz,technical_child boolean NOT NULL DEFAULT false,
 CHECK((execution_id IS NULL)=(released_at IS NULL))
);
CREATE INDEX workflow_waiting ON automation.workflow_requests(stage,requested_at,job_id) WHERE released_at IS NULL;
CREATE INDEX workflow_correlation ON automation.workflow_requests(correlation_id,stage,requested_at DESC);
CREATE INDEX workflow_recent ON automation.workflow_requests(requested_at DESC,job_id);
CREATE INDEX workflow_last_release ON automation.workflow_requests(stage,released_at DESC)
 INCLUDE(execution_id,workflow_id) WHERE released_at IS NOT NULL;
CREATE INDEX workflow_paused ON automation.workflow_runs(correlation_id) WHERE paused;
CREATE INDEX workflow_run_jobs ON automation.jobs(correlation_id,created_at) WHERE runtime_version=1;
CREATE FUNCTION automation.workflow_enabled() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
 SET search_path=pg_catalog AS $$ SELECT enabled FROM automation.workflow_settings WHERE singleton $$;
CREATE FUNCTION automation.workflow_stage(p_type text) RETURNS text LANGUAGE sql IMMUTABLE
 SET search_path=pg_catalog AS $$ SELECT CASE
 WHEN p_type LIKE 'cve.import.%' THEN 'import'
 WHEN p_type LIKE 'inventory.%' THEN 'inventory'
 WHEN p_type LIKE 'cve.enrich.%' OR p_type LIKE 'cve.epss.%' THEN 'enrichment'
 WHEN p_type='matching.index_v5_batch' THEN 'index'
 WHEN p_type LIKE 'matching.%' THEN 'matching'
 WHEN p_type LIKE 'findings.%' THEN 'findings'
 WHEN p_type LIKE 'notifications.%' THEN 'notifications'
 WHEN p_type='status.collect' THEN 'status' END $$;
GRANT USAGE ON SCHEMA automation,cve TO workflow_control;
GRANT SELECT ON automation.workflow_settings,automation.workflow_runs,automation.workflow_requests TO api_security,reporter;
REVOKE ALL ON FUNCTION automation.workflow_enabled(),automation.workflow_stage(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.workflow_enabled(),automation.workflow_stage(text)
 TO api_security,api_ingest,inventory_processor,importer,enricher,matcher,findings_writer,notification,status_probe,workflow_control;

-- Turn an executable task into a durable stage request, in the original enqueue transaction.
-- The workflow graph lives in n8n. Only same-stage technical subdivisions inherit authorization.
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('automation.enqueue_job(text,integer,jsonb,text,uuid,integer,timestamptz,timestamptz,integer,text,boolean,uuid)'::regprocedure) INTO definition;
 definition:=replace(definition,'DECLARE j automation.jobs;',
 'DECLARE flow_stage text; gated boolean:=false; request_created boolean; inherited automation.workflow_requests; slot bigint; j automation.jobs;');
 definition:=replace(definition,'actor:=session_user||'':''||p_scope;',
 'flow_stage:=automation.workflow_stage(p_type);
 IF automation.workflow_enabled() AND flow_stage IS NOT NULL THEN
  gated:=true;
  IF t.handler_role=session_user AND (session_user<>''matcher'' OR p_scope=''matching-internal'') THEN
   SELECT r.* INTO inherited FROM automation.workflow_requests r
   WHERE r.correlation_id=p_correlation AND r.stage=flow_stage AND r.released_at IS NOT NULL
   ORDER BY r.released_at DESC LIMIT 1;
  END IF;
  p_pending:=true;
 END IF;
 actor:=session_user||'':''||p_scope;');
 definition:=replace(definition,' RETURN j;',
 ' IF gated THEN
  p_correlation:=j.correlation_id;
  INSERT INTO automation.workflow_runs(correlation_id) VALUES(p_correlation) ON CONFLICT DO NOTHING;
  INSERT INTO automation.workflow_requests(job_id,correlation_id,stage)
  VALUES(j.id,p_correlation,flow_stage) ON CONFLICT DO NOTHING;
  request_created:=FOUND;
  IF inherited.job_id IS NOT NULL THEN
   UPDATE automation.workflow_requests SET execution_id=inherited.execution_id,workflow_id=inherited.workflow_id,
    workflow_version=inherited.workflow_version,released_at=clock_timestamp(),technical_child=true
   WHERE job_id=j.id AND released_at IS NULL;
   UPDATE automation.jobs SET status=''queued'',updated_at=clock_timestamp() WHERE id=j.id AND status=''pending'';
  ELSIF request_created AND j.status=''pending'' THEN
   slot:=floor(extract(epoch FROM clock_timestamp())/5);
   PERFORM automation.emit_event(gen_random_uuid(),''workflow.''||session_user||''.''||flow_stage,1,
    ''workflow-''||replace(session_user::text,''_'',''-''),''workflow_stage'',flow_stage,slot,
    jsonb_build_object(''stage'',flow_stage,''slot'',slot),
    encode(sha256(convert_to(flow_stage||'':''||slot::text,''UTF8'')),''hex''),p_correlation);
  END IF;
  SELECT * INTO j FROM automation.jobs WHERE id=j.id;
 END IF;
 RETURN j;');
 IF strpos(definition,'workflow_requests')=0 THEN RAISE EXCEPTION 'Unexpected enqueue definition'; END IF;
 EXECUTE definition;
END $$;

-- Defense in depth: neither administrative release nor a direct job update bypasses n8n.
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('automation.control_job(uuid,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'IF p_action=''release'' AND j.status=''pending'' THEN',
 'IF p_action=''release'' AND EXISTS(SELECT 1 FROM automation.workflow_requests WHERE job_id=p_id AND released_at IS NULL)
 THEN RAISE EXCEPTION ''n8n authorization required'' USING ERRCODE=''42501'';
 ELSIF p_action=''release'' AND j.status=''pending'' THEN');
 EXECUTE definition;
 SELECT pg_get_functiondef('automation.claim_job(text[],uuid,double precision)'::regprocedure) INTO definition;
 definition:=replace(definition,'AND q.status IN (''queued'',''retry_pending'')',
 'AND NOT EXISTS(SELECT 1 FROM automation.workflow_requests wr JOIN automation.workflow_runs r USING(correlation_id)
 WHERE wr.job_id=q.id AND (wr.released_at IS NULL OR r.paused OR r.cancelled))
 AND q.status IN (''queued'',''retry_pending'')');
 EXECUTE definition;
END $$;

-- Wakes are coalesced by stage/producer/five-second slot. n8n also reconciles periodically.
DO $$ DECLARE producer name; stage text; BEGIN
 FOREACH producer IN ARRAY ARRAY['api_security','api_ingest','inventory_processor','importer','enricher',
 'matcher','findings_writer','notification','status_probe','workflow_control']::name[] LOOP
  FOREACH stage IN ARRAY ARRAY['import','inventory','enrichment','index','matching','findings','notifications','status'] LOOP
   INSERT INTO automation.event_types(code,producer_role,source)
   VALUES('workflow.'||producer||'.'||stage,producer,'workflow-'||replace(producer::text,'_','-'));
  END LOOP;
 END LOOP;
END $$;
GRANT EXECUTE ON FUNCTION automation.emit_event(uuid,text,integer,text,text,text,bigint,jsonb,text,uuid) TO workflow_control;

CREATE FUNCTION automation.workflow_dispatch(p_stage text,p_execution text,p_workflow text,p_limit integer DEFAULT 64)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE request record; n integer:=0;
BEGIN
 IF session_user<>'workflow_control' OR p_stage NOT IN ('import','inventory','enrichment','index','matching','findings','notifications','status')
 OR p_execution !~ '^[A-Za-z0-9_-]{1,128}$' OR p_workflow IS DISTINCT FROM 'cve-control-'||p_stage
 OR p_limit NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'workflow authorization denied' USING ERRCODE='42501'; END IF;
 IF NOT automation.workflow_enabled() THEN RETURN jsonb_build_object('enabled',false,'released',0,'more',false); END IF;
 -- Concurrent webhook and timer executions cannot race on one stage. SKIP LOCKED bounds work.
 FOR request IN SELECT wr.job_id FROM automation.workflow_requests wr
 JOIN automation.workflow_runs r USING(correlation_id) JOIN automation.jobs j ON j.id=wr.job_id
 WHERE wr.stage=p_stage AND wr.released_at IS NULL AND NOT r.paused AND NOT r.cancelled
 AND j.status='pending' ORDER BY wr.requested_at,wr.job_id
 FOR UPDATE OF wr,j SKIP LOCKED LIMIT p_limit LOOP
  UPDATE automation.workflow_requests SET execution_id=p_execution,workflow_id=p_workflow,workflow_version=1,
   released_at=clock_timestamp() WHERE job_id=request.job_id;
  UPDATE automation.jobs SET status='queued',updated_at=clock_timestamp() WHERE id=request.job_id;
  n:=n+1;
 END LOOP;
 IF n>0 THEN
 INSERT INTO security.audit_log(action,object_type,object_id,outcome,metadata)
 VALUES('workflow.stage_released','workflow_stage',p_stage,'success',
 jsonb_build_object('execution',p_execution,'workflow',p_workflow,'released',n));
 END IF;
 RETURN jsonb_build_object('enabled',true,'released',n,'more',n=p_limit);
END $$;
REVOKE ALL ON FUNCTION automation.workflow_dispatch(text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.workflow_dispatch(text,text,text,integer) TO workflow_control;

INSERT INTO security.audit_actions(action,writer_role) VALUES
 ('workflow.settings_changed','api_security'),('workflow.run_controlled','api_security'),('workflow.stage_released','postgres_owner');

-- Only n8n may request regular status/maintenance ticks. No domain database access for n8n itself.
UPDATE automation.job_types SET producer_roles=array_append(producer_roles,'workflow_control'::name)
 WHERE code IN ('status.collect','findings.maintenance','notifications.maintenance','cve.import.cve_list');
GRANT EXECUTE ON FUNCTION automation.enqueue_job(text,integer,jsonb,text,uuid,integer,timestamptz,timestamptz,integer,text,boolean,uuid) TO workflow_control;
CREATE FUNCTION automation.workflow_tick(p_stage text,p_execution text,p_workflow text)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE kind text; slot bigint; cfg automation.workflow_settings; active uuid; rid uuid; mode text; correlation uuid;
BEGIN
 IF session_user<>'workflow_control' OR p_stage NOT IN ('import','status','findings','notifications')
 OR p_execution !~ '^[A-Za-z0-9_-]{1,128}$' OR p_workflow IS DISTINCT FROM 'cve-control-'||p_stage
 THEN RAISE EXCEPTION 'workflow tick denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO cfg FROM automation.workflow_settings WHERE singleton FOR UPDATE;
 IF NOT cfg.enabled THEN RETURN jsonb_build_object('scheduled',false); END IF;
 slot:=floor(extract(epoch FROM clock_timestamp())/CASE WHEN p_stage='status' THEN 30 ELSE 60 END);
 correlation:=gen_random_uuid();
 IF p_stage='import' THEN
  IF NOT cfg.auto_updates OR cfg.next_update_at>clock_timestamp() THEN RETURN jsonb_build_object('scheduled',false); END IF;
  SELECT r.id INTO active FROM cve.import_runs r JOIN cve.import_run_status s ON s.id=r.id
   WHERE r.source_id='cve_list' AND s.effective_status IN ('planned','running') ORDER BY r.created_at DESC LIMIT 1;
  IF active IS NULL THEN
   mode:=CASE WHEN EXISTS(SELECT 1 FROM cve.import_runs WHERE source_id='cve_list' AND status='completed') THEN 'incremental' ELSE 'initial' END;
   rid:=cve.schedule_import('cve_list',mode,jsonb_build_object('configuration',cfg.source_config),
    'n8n-update:'||slot::text,correlation);
  END IF;
  UPDATE automation.workflow_settings SET next_update_at=clock_timestamp()+make_interval(secs=>cfg.update_interval) WHERE singleton;
 ELSE
  kind:=CASE p_stage WHEN 'status' THEN 'status.collect' ELSE p_stage||'.maintenance' END;
  PERFORM automation.enqueue_job(kind,1,'{}'::jsonb,'n8n-tick:'||slot::text,correlation,
   0,NULL,NULL,CASE WHEN p_stage='status' THEN 1 ELSE 3 END,'n8n-tick',false);
 END IF;
 RETURN jsonb_build_object('scheduled',true);
END $$;
REVOKE ALL ON FUNCTION automation.workflow_tick(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.workflow_tick(text,text,text) TO workflow_control;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('cve.schedule_import(text,text,jsonb,text,uuid)'::regprocedure) INTO definition;
 definition:=replace(definition,'''api_security'',''importer''','''api_security'',''importer'',''workflow_control''');
 definition:=replace(definition,' IF session_user NOT IN',
 ' IF session_user=''workflow_control'' AND (p_source IS DISTINCT FROM ''cve_list''
 OR p_context->''configuration''->''enabled'' IS DISTINCT FROM ''["cve_list"]''::jsonb
 OR p_context->''configuration''->>''cve_list_transport'' IS DISTINCT FROM ''git''
 OR p_context->''configuration''->''epss_enabled'' IS DISTINCT FROM ''false''::jsonb)
 THEN RAISE EXCEPTION ''Only V5 Git updates authorized'' USING ERRCODE=''42501''; END IF;
 IF session_user NOT IN');
 EXECUTE definition;
END $$;
GRANT EXECUTE ON FUNCTION cve.schedule_import(text,text,jsonb,text,uuid) TO workflow_control;

CREATE FUNCTION automation.workflow_summary() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog SET jit=off AS $$
WITH scope AS MATERIALIZED (
 SELECT job_id,stage FROM automation.workflow_requests WHERE released_at IS NULL
 UNION SELECT job_id,stage FROM automation.workflow_requests WHERE requested_at>clock_timestamp()-interval '24 hours'
 UNION SELECT w.job_id,w.stage FROM automation.workflow_runs r JOIN automation.workflow_requests w USING(correlation_id) WHERE r.paused
), counts AS (
 SELECT w.stage,count(*) FILTER(WHERE j.status='pending') AS waiting,
 count(*) FILTER(WHERE j.status IN ('queued','retry_pending')) AS queued,
 count(*) FILTER(WHERE j.status='running') AS running,
 count(*) FILTER(WHERE j.status IN ('failed','timed_out')) AS failed
 FROM scope w JOIN automation.jobs j ON j.id=w.job_id GROUP BY w.stage
)
 SELECT jsonb_build_object('enabled',s.enabled,'auto_updates',s.auto_updates,'update_interval',s.update_interval,
 'next_update_at',s.next_update_at,'stages',(SELECT jsonb_agg(jsonb_build_object(
 'stage',v.stage,'waiting',coalesce(c.waiting,0),'queued',coalesce(c.queued,0),
 'running',coalesce(c.running,0),'failed',coalesce(c.failed,0),'last_release',last.released_at,
 'last_execution',CASE WHEN last.execution_id IS NOT NULL THEN jsonb_build_object('id',last.execution_id,'workflow',last.workflow_id) END))
 FROM unnest(ARRAY['import','inventory','enrichment','index','matching','findings','notifications','status']) v(stage)
 LEFT JOIN counts c USING(stage) LEFT JOIN LATERAL (
 SELECT released_at,execution_id,workflow_id FROM automation.workflow_requests WHERE stage=v.stage AND released_at IS NOT NULL
 ORDER BY released_at DESC LIMIT 1) last ON true))
 FROM automation.workflow_settings s WHERE singleton $$;
REVOKE ALL ON FUNCTION automation.workflow_summary() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.workflow_summary() TO api_security,reporter,workflow_control,status_probe;
GRANT UPDATE(auto_updates,update_interval,next_update_at,updated_at) ON automation.workflow_settings TO api_security;
GRANT SELECT ON automation.jobs TO api_security;

CREATE FUNCTION automation.workflow_run_control(p_correlation uuid,p_action text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'api_security' OR p_action NOT IN ('pause','resume','cancel') THEN RAISE EXCEPTION 'workflow control denied' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT 1 FROM automation.workflow_runs WHERE correlation_id=p_correlation AND cancelled) THEN RETURN false; END IF;
 UPDATE automation.workflow_runs SET paused=(p_action='pause'),cancelled=(p_action='cancel'),updated_at=clock_timestamp()
 WHERE correlation_id=p_correlation;
 IF NOT FOUND THEN RETURN false; END IF;
 IF p_action='cancel' THEN
  UPDATE automation.jobs j SET cancel_requested=true,
   status=CASE WHEN j.status='running' THEN j.status ELSE 'cancelled' END,
   finished_at=CASE WHEN j.status='running' THEN NULL ELSE clock_timestamp() END
  FROM automation.workflow_requests wr WHERE wr.job_id=j.id AND wr.correlation_id=p_correlation
  AND j.status IN ('pending','queued','retry_pending','running');
 END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION automation.workflow_run_control(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.workflow_run_control(uuid,text) TO api_security;

INSERT INTO automation.job_types(code,handler_role,producer_roles,runtime_seconds,max_attempts)
 VALUES('matching.evaluate_v5_batch','matcher',ARRAY['matcher','workflow_control']::name[],3600,3);
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00039_native_v5_json','00040_workflow_control');
END $$;
"""
