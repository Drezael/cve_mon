"""A durable FIFO inbox: only n8n turns commands and proposed tasks into execution."""

from alembic import op

revision = "00048_n8n_message_queue"
down_revision = "00047_erasure_presentation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)
    definition = driver.execute(
        "SELECT pg_get_functiondef('inventory.erase_server(uuid,uuid)'::regprocedure)"
    ).fetchone()[0]
    parent_selector = """
   SELECT string_agg(format('parent.%I=(marked.key->>%L)::%s',a.attname,a.attname,
    format_type(a.atttypid,a.atttypmod)),' AND ') INTO pk_join FROM pg_index i
    JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=ANY(i.indkey)
    WHERE i.indrelid=fk.confrelid AND i.indisprimary;
"""
    row_selector = """
  SELECT string_agg(format('row.%I=(marked.key->>%L)::%s',a.attname,a.attname,
   format_type(a.atttypid,a.atttypmod)),' AND ') INTO pk_join FROM pg_index i
   JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=ANY(i.indkey)
   WHERE i.indrelid=rel.rel AND i.indisprimary;
"""
    changes = [
        (
            "   EXECUTE format('INSERT INTO pg_temp.server_purge_rows SELECT %s,inventory.purge_primary_key(%s,to_jsonb(child))",
            parent_selector
            + "   EXECUTE format('INSERT INTO pg_temp.server_purge_rows SELECT %s,inventory.purge_primary_key(%s,to_jsonb(child))",
        ),
        ("AND to_jsonb(parent) @> marked.key ON CONFLICT", "AND %s ON CONFLICT"),
        ("join_clause,fk.confrelid);", "join_clause,fk.confrelid,pk_join);"),
        (
            "  EXECUTE format('DELETE FROM %s row USING",
            row_selector + "  EXECUTE format('DELETE FROM %s row USING",
        ),
        (
            "AND to_jsonb(row) @> marked.key',rel.rel::regclass,rel.rel);",
            "AND %s',rel.rel::regclass,rel.rel,pk_join);",
        ),
        (
            "INSERT INTO pg_temp.server_purge_rows SELECT %s,inventory.purge_primary_key(%s,to_jsonb(row)) FROM %s row WHERE EXISTS(SELECT 1 FROM pg_temp.server_purge_ids ids WHERE strpos(to_jsonb(row)::text,ids.id)>0) ON CONFLICT DO NOTHING",
            "WITH candidate AS MATERIALIZED (SELECT %s::oid rel,inventory.purge_primary_key(%s,to_jsonb(row)) key,to_jsonb(row)::text document FROM %s row) INSERT INTO pg_temp.server_purge_rows SELECT rel,key FROM candidate WHERE EXISTS(SELECT 1 FROM pg_temp.server_purge_ids ids WHERE strpos(document,ids.id)>0) ON CONFLICT DO NOTHING",
        ),
    ]
    for old, new in changes:
        if old not in definition:
            raise RuntimeError("Erasure index patch did not match the preceding migration")
        definition = definition.replace(old, new)
    driver.execute(definition, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Do not discard queued orchestration commands or receipts")


DDL = r"""
CREATE TABLE automation.n8n_queue (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 kind text NOT NULL CHECK(kind IN ('command','task','result','event')),
 producer name NOT NULL, message_type text NOT NULL,
 payload jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(payload)='object' AND system.safe_metadata(payload)),
 job_id uuid REFERENCES automation.jobs(id) DEFERRABLE INITIALLY IMMEDIATE, event_id uuid REFERENCES automation.event_outbox(id) DEFERRABLE INITIALLY IMMEDIATE,
 notification_id uuid REFERENCES automation.notification_intents(id) DEFERRABLE INITIALLY IMMEDIATE,
 actor_id uuid REFERENCES security.users(id) DEFERRABLE INITIALLY IMMEDIATE, correlation_id uuid NOT NULL,
 deduplication_key text NOT NULL UNIQUE,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','processing','completed','failed','cancelled')),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), started_at timestamptz, finished_at timestamptz,
 lease_token uuid, lease_until timestamptz, attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
 execution_id text, workflow_id text, error_code text, result jsonb,
 CHECK((lease_token IS NULL)=(lease_until IS NULL))
);
CREATE INDEX n8n_queue_fifo ON automation.n8n_queue(sequence) WHERE state IN ('pending','processing');
CREATE INDEX n8n_queue_correlation ON automation.n8n_queue(correlation_id,sequence);
CREATE INDEX n8n_queue_commands ON automation.n8n_queue(message_type,state,sequence) WHERE kind='command';
CREATE INDEX n8n_queue_job ON automation.n8n_queue(job_id);
GRANT SELECT ON automation.n8n_queue TO api_security,reporter,workflow_control;
REVOKE ALL ON automation.n8n_queue FROM PUBLIC;

-- Preserve the proven import/resume implementation, but make its execution n8n-only.
ALTER FUNCTION cve.dashboard_request_update(uuid,uuid,jsonb) RENAME TO execute_queued_update;
REVOKE ALL ON FUNCTION cve.execute_queued_update(uuid,uuid,jsonb) FROM api_security;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('cve.execute_queued_update(uuid,uuid,jsonb)'::regprocedure) INTO definition;
 EXECUTE replace(definition,'session_user<>''api_security''','session_user<>''workflow_control''');
END $$;
CREATE FUNCTION cve.dashboard_request_update(p_key uuid,p_actor uuid,p_config jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE item automation.n8n_queue; BEGIN
 IF session_user<>'api_security' OR p_actor IS NULL OR p_key IS NULL
 OR p_config->'enabled' IS DISTINCT FROM '["cve_list"]'::jsonb
 OR p_config->>'cve_list_transport' IS DISTINCT FROM 'git'
 OR p_config->>'epss_enabled' IS DISTINCT FROM 'false'
 OR NOT system.safe_metadata(p_config)
 THEN RAISE EXCEPTION 'invalid update command' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(833001);
 SELECT * INTO item FROM automation.n8n_queue WHERE deduplication_key='cve-update:'||p_key::text;
 IF item.id IS NOT NULL AND item.actor_id<>p_actor THEN
  RAISE EXCEPTION 'request conflict' USING ERRCODE='23505'; END IF;
 IF item.id IS NULL THEN
  INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,actor_id,correlation_id,deduplication_key)
  VALUES('command',session_user,'cve.refresh',jsonb_build_object('configuration',p_config,'request_id',p_key),p_actor,p_key,'cve-update:'||p_key::text)
  RETURNING * INTO item;
 END IF;
 RETURN jsonb_build_array(jsonb_build_object('source','cve_list','id',item.id));
END $$;
REVOKE ALL ON FUNCTION cve.dashboard_request_update(uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cve.dashboard_request_update(uuid,uuid,jsonb) TO api_security;

CREATE FUNCTION automation.n8n_capture() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j automation.jobs; BEGIN
 IF TG_TABLE_NAME='workflow_requests' THEN
  SELECT * INTO STRICT j FROM automation.jobs WHERE id=NEW.job_id;
  INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,job_id,correlation_id,deduplication_key)
  VALUES('task',j.creator_role,j.job_type,jsonb_build_object('stage',NEW.stage),j.id,j.correlation_id,'task:'||j.id::text) ON CONFLICT DO NOTHING;
 ELSIF TG_TABLE_NAME='jobs' THEN
  IF automation.workflow_enabled() AND NEW.runtime_version=1 AND NEW.status IN ('succeeded','failed','timed_out','cancelled')
   AND OLD.status IS DISTINCT FROM NEW.status THEN
   INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,job_id,correlation_id,deduplication_key)
   VALUES('result',session_user,NEW.job_type,jsonb_build_object('status',NEW.status,'error_code',NEW.error_code,'result_reference',NEW.result_reference),NEW.id,NEW.correlation_id,
    'result:'||NEW.id::text||':'||NEW.status||':'||NEW.attempts::text) ON CONFLICT DO NOTHING;
  END IF;
 ELSIF TG_TABLE_NAME='event_outbox' THEN
  IF automation.workflow_enabled() AND NEW.runtime_version=1 AND NEW.event_type NOT LIKE 'workflow.%' THEN
  INSERT INTO automation.n8n_queue(kind,producer,message_type,event_id,correlation_id,deduplication_key)
  VALUES('event',session_user,NEW.event_type,NEW.id,NEW.correlation_id,'event:'||NEW.id::text) ON CONFLICT DO NOTHING;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER n8n_task AFTER INSERT ON automation.workflow_requests FOR EACH ROW EXECUTE FUNCTION automation.n8n_capture();
CREATE TRIGGER n8n_result AFTER UPDATE ON automation.jobs FOR EACH ROW EXECUTE FUNCTION automation.n8n_capture();
CREATE TRIGGER n8n_event AFTER INSERT ON automation.event_outbox FOR EACH ROW EXECUTE FUNCTION automation.n8n_capture();
INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,job_id,correlation_id,deduplication_key)
 SELECT 'task',j.creator_role,j.job_type,jsonb_build_object('stage',w.stage),j.id,j.correlation_id,'task:'||j.id::text
 FROM automation.workflow_requests w JOIN automation.jobs j ON j.id=w.job_id WHERE w.released_at IS NULL AND j.status='pending'
 ORDER BY w.requested_at,j.created_at,j.id;
-- Transport components publish results without copying credentials, recipients or message bodies.
CREATE FUNCTION automation.n8n_transport_result() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE notification automation.notification_intents; correlation uuid; BEGIN
 IF NOT automation.workflow_enabled() THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='event_deliveries' THEN
  IF NEW.runtime_version<>1 OR NEW.status NOT IN ('delivered','failed','retry_pending') OR NEW.status=OLD.status THEN RETURN NEW; END IF;
  SELECT correlation_id INTO correlation FROM automation.event_outbox WHERE id=NEW.event_id;
  INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,event_id,correlation_id,deduplication_key)
  VALUES('result',session_user,'event.delivery',jsonb_build_object('status',NEW.status,'destination',NEW.destination,'error_code',NEW.last_error_code),
   NEW.event_id,correlation,'delivery:'||NEW.event_id::text||':'||NEW.destination||':'||NEW.attempts::text||':'||NEW.status) ON CONFLICT DO NOTHING;
 ELSIF TG_TABLE_NAME='notification_delivery_results' THEN
  SELECT n.* INTO STRICT notification FROM automation.notification_intents n
   JOIN automation.notification_delivery_attempts a ON a.notification_id=n.id WHERE a.id=NEW.attempt_id;
  INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,event_id,notification_id,correlation_id,deduplication_key)
  VALUES('result',session_user,'notification.transport',jsonb_build_object('status',NEW.status,'smtp_code',NEW.smtp_code),
   notification.event_id,notification.id,notification.correlation_id,'smtp-result:'||NEW.attempt_id::text) ON CONFLICT DO NOTHING;
 ELSIF TG_TABLE_NAME='notification_transport_evidence' THEN
  SELECT * INTO STRICT notification FROM automation.notification_intents WHERE id=NEW.notification_id;
  INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,event_id,notification_id,correlation_id,deduplication_key)
  VALUES('result',session_user,'notification.evidence',jsonb_build_object('status',NEW.status),
   notification.event_id,notification.id,notification.correlation_id,'smtp-evidence:'||NEW.id::text) ON CONFLICT DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER n8n_delivery AFTER UPDATE ON automation.event_deliveries FOR EACH ROW EXECUTE FUNCTION automation.n8n_transport_result();
CREATE TRIGGER n8n_smtp_result AFTER INSERT ON automation.notification_delivery_results FOR EACH ROW EXECUTE FUNCTION automation.n8n_transport_result();
CREATE TRIGGER n8n_smtp_evidence AFTER INSERT ON automation.notification_transport_evidence FOR EACH ROW EXECUTE FUNCTION automation.n8n_transport_result();

-- Backoff/recovery requests also return to n8n rather than executing another attempt directly.
CREATE FUNCTION automation.n8n_retry_gate() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.runtime_version=1 AND NEW.status='retry_pending' AND automation.workflow_enabled()
 AND EXISTS(SELECT 1 FROM automation.workflow_requests WHERE job_id=NEW.id) THEN
  INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,job_id,correlation_id,deduplication_key)
   VALUES('result',session_user,NEW.job_type,jsonb_build_object('status','retry_pending','error_code',NEW.error_code),NEW.id,NEW.correlation_id,
    'retry-result:'||NEW.id::text||':'||NEW.attempts::text) ON CONFLICT DO NOTHING;
  UPDATE automation.workflow_requests SET released_at=NULL,execution_id=NULL,workflow_id=NULL,workflow_version=NULL,
   technical_child=false,requested_at=clock_timestamp() WHERE job_id=NEW.id;
  INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,job_id,correlation_id,deduplication_key,available_at)
   VALUES('task',session_user,NEW.job_type,jsonb_build_object('stage',automation.workflow_stage(NEW.job_type)),NEW.id,NEW.correlation_id,
    'retry-task:'||NEW.id::text||':'||NEW.attempts::text,NEW.scheduled_at) ON CONFLICT DO NOTHING;
  NEW.status:='pending';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER n8n_retry BEFORE UPDATE ON automation.jobs FOR EACH ROW EXECUTE FUNCTION automation.n8n_retry_gate();

-- Every technical subdivision also waits for a queue receipt; no inherited execution bypass.
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('automation.enqueue_job(text,integer,jsonb,text,uuid,integer,timestamptz,timestamptz,integer,text,boolean,uuid)'::regprocedure) INTO definition;
 EXECUTE replace(definition,'IF inherited.job_id IS NOT NULL THEN','IF false THEN');
END $$;

CREATE FUNCTION automation.n8n_claim(p_execution text,p_workflow text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE item automation.n8n_queue; BEGIN
 IF session_user<>'workflow_control' OR p_workflow<>'cve-control-queue' OR p_execution !~ '^[A-Za-z0-9_-]{1,128}$'
 THEN RAISE EXCEPTION 'n8n queue context required' USING ERRCODE='42501'; END IF;
 IF NOT automation.workflow_enabled() THEN RETURN jsonb_build_object('kind','empty'); END IF;
 PERFORM pg_advisory_xact_lock(7348001);
 LOOP
  SELECT * INTO item FROM automation.n8n_queue q WHERE state IN ('pending','processing') AND available_at<=clock_timestamp() AND NOT EXISTS(SELECT 1 FROM automation.workflow_runs r WHERE r.correlation_id=q.correlation_id AND r.paused AND NOT r.cancelled) ORDER BY sequence LIMIT 1 FOR UPDATE;
  IF item.id IS NULL OR (item.state='processing' AND item.lease_until>clock_timestamp()) THEN RETURN jsonb_build_object('kind','empty'); END IF;
  IF item.attempts>=5 THEN
   UPDATE automation.n8n_queue SET state='failed',finished_at=clock_timestamp(),lease_token=NULL,lease_until=NULL,error_code='lease_exhausted' WHERE id=item.id;
   CONTINUE;
  END IF;
  IF EXISTS(SELECT 1 FROM automation.workflow_runs WHERE correlation_id=item.correlation_id AND paused AND NOT cancelled)
  THEN RETURN jsonb_build_object('kind','empty'); END IF;
  IF EXISTS(SELECT 1 FROM automation.workflow_runs WHERE correlation_id=item.correlation_id AND cancelled) THEN
   UPDATE automation.n8n_queue SET state='cancelled',finished_at=clock_timestamp(),lease_token=NULL,lease_until=NULL WHERE id=item.id;
   CONTINUE;
  END IF;
  UPDATE automation.n8n_queue SET state='processing',started_at=coalesce(started_at,clock_timestamp()),attempts=attempts+1,
   lease_token=gen_random_uuid(),lease_until=clock_timestamp()+interval '30 seconds',execution_id=p_execution,workflow_id=p_workflow
   WHERE id=item.id RETURNING * INTO item;
  RETURN jsonb_build_object('id',item.id,'sequence',item.sequence,'kind',item.kind,'message_type',item.message_type,
   'stage',item.payload->>'stage','payload',item.payload,'job_id',item.job_id,'event_id',item.event_id,'notification_id',item.notification_id,'lease_token',item.lease_token);
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION automation.n8n_claim(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.n8n_claim(text,text) TO workflow_control;

CREATE FUNCTION automation.n8n_retry_import(p_id uuid) RETURNS uuid
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old automation.jobs; result uuid; BEGIN
 IF session_user<>'workflow_control' THEN RAISE EXCEPTION 'n8n required' USING ERRCODE='42501'; END IF;
 SELECT * INTO old FROM automation.jobs WHERE id=p_id AND job_type='cve.import.cve_list'
 AND status IN ('failed','timed_out','cancelled') FOR UPDATE;
 IF old.id IS NULL THEN RAISE EXCEPTION 'import not retryable' USING ERRCODE='23514'; END IF;
 SELECT id INTO result FROM automation.enqueue_job(old.job_type,old.payload_version,old.payload,gen_random_uuid()::text,
 old.correlation_id,old.priority,NULL,NULL,old.max_attempts,'replay',false,old.id);
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION automation.n8n_retry_import(uuid) FROM PUBLIC;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('cve.execute_queued_update(uuid,uuid,jsonb)'::regprocedure) INTO definition;
 EXECUTE replace(definition,'automation.control_job(old.job_id,''replay'')','automation.n8n_retry_import(old.job_id)');
END $$;

CREATE FUNCTION automation.n8n_decide(p_id uuid,p_token uuid,p_kind text,p_execution text,p_workflow text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE item automation.n8n_queue; answer jsonb:='{}'; stage text; active uuid; BEGIN
 IF session_user<>'workflow_control' OR p_workflow<>'cve-control-queue' THEN RAISE EXCEPTION 'n8n required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(7348001);
 SELECT * INTO item FROM automation.n8n_queue WHERE id=p_id FOR UPDATE;
 -- An HTTP retry after commit must return the existing receipt without repeating a command.
 IF item.state='completed' AND item.lease_token IS NULL AND item.execution_id=p_execution AND item.workflow_id=p_workflow
 THEN RETURN jsonb_build_object('processed',true,'id',item.id); END IF;
 IF item.state IS DISTINCT FROM 'processing' OR item.kind IS DISTINCT FROM p_kind OR item.lease_token IS DISTINCT FROM p_token
 OR item.execution_id IS DISTINCT FROM p_execution OR item.lease_until<=clock_timestamp()
 THEN RAISE EXCEPTION 'stale queue receipt' USING ERRCODE='42501'; END IF;
 IF item.kind='command' THEN
  IF item.message_type<>'cve.refresh' THEN RAISE EXCEPTION 'unsupported command'; END IF;
  -- Recheck the requesting user's permissions after time spent in the queue.
  IF item.actor_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM security.users u
   JOIN security.user_roles ur ON ur.user_id=u.id JOIN security.role_permissions rp ON rp.role_id=ur.role_id
   WHERE u.id=item.actor_id AND u.status='active' AND rp.permission_code='cve:update') THEN
   UPDATE automation.n8n_queue SET state='cancelled',error_code='requester_unavailable',finished_at=clock_timestamp(),lease_token=NULL,lease_until=NULL WHERE id=item.id;
   RETURN jsonb_build_object('processed',true,'cancelled',true);
  END IF;
  IF item.actor_id IS NULL THEN
   SELECT id INTO active FROM cve.import_run_status WHERE source_id='cve_list' AND effective_status IN ('planned','running') ORDER BY created_at DESC LIMIT 1;
   IF active IS NOT NULL THEN answer:=jsonb_build_array(jsonb_build_object('source','cve_list','id',active));
   ELSE answer:=jsonb_build_array(jsonb_build_object('source','cve_list','id',cve.schedule_import('cve_list',
    CASE WHEN EXISTS(SELECT 1 FROM cve.import_runs WHERE source_id='cve_list' AND status='completed') THEN 'incremental' ELSE 'initial' END,
    jsonb_build_object('configuration',item.payload->'configuration'),item.deduplication_key,item.correlation_id))); END IF;
  ELSE
   answer:=cve.execute_queued_update((item.payload->>'request_id')::uuid,item.actor_id,item.payload->'configuration');
  END IF;
 ELSIF item.kind='task' THEN
  stage:=item.payload->>'stage';
  UPDATE automation.workflow_requests SET execution_id=p_execution,workflow_id=p_workflow,workflow_version=1,released_at=clock_timestamp()
   WHERE job_id=item.job_id AND released_at IS NULL;
  UPDATE automation.jobs SET status='queued',updated_at=clock_timestamp() WHERE id=item.job_id AND status='pending';
  answer:=jsonb_build_object('job_id',item.job_id,'stage',stage);
 ELSE
  answer:=item.payload;
 END IF;
 UPDATE automation.n8n_queue SET state='completed',result=answer,finished_at=clock_timestamp(),lease_token=NULL,lease_until=NULL WHERE id=item.id;
 RETURN jsonb_build_object('processed',true,'id',item.id);
END $$;
REVOKE ALL ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) TO workflow_control;

-- Existing stage endpoints remain compatible, but can never overtake the FIFO head.
CREATE OR REPLACE FUNCTION automation.workflow_dispatch(p_stage text,p_execution text,p_workflow text,p_limit integer DEFAULT 64)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE item automation.n8n_queue; claimed jsonb; n integer:=0; i integer; BEGIN
 IF session_user<>'workflow_control' OR p_workflow IS DISTINCT FROM 'cve-control-'||p_stage
 OR p_stage NOT IN ('import','inventory','enrichment','index','matching','findings','notifications','status')
 OR p_execution !~ '^[A-Za-z0-9_-]{1,128}$' OR p_limit NOT BETWEEN 1 AND 128
 THEN RAISE EXCEPTION 'workflow authorization denied' USING ERRCODE='42501'; END IF;
 IF NOT automation.workflow_enabled() THEN RETURN jsonb_build_object('released',0,'more',false); END IF;
 PERFORM pg_advisory_xact_lock(7348001);
 FOR i IN 1..p_limit LOOP
  SELECT * INTO item FROM automation.n8n_queue q WHERE state IN ('pending','processing') AND available_at<=clock_timestamp() AND NOT EXISTS(SELECT 1 FROM automation.workflow_runs r WHERE r.correlation_id=q.correlation_id AND r.paused AND NOT r.cancelled) ORDER BY sequence LIMIT 1;
  IF item.id IS NULL OR item.kind='command' OR item.state='processing'
   OR (item.kind='task' AND item.payload->>'stage'<>p_stage) THEN EXIT; END IF;
  claimed:=automation.n8n_claim(p_execution,'cve-control-queue');
  IF claimed->>'kind'='empty' THEN EXIT; END IF;
  PERFORM automation.n8n_decide(item.id,(claimed->>'lease_token')::uuid,item.kind,p_execution,'cve-control-queue');
  UPDATE automation.n8n_queue SET workflow_id=p_workflow WHERE id=item.id;
  IF item.kind='task' THEN
   UPDATE automation.workflow_requests SET workflow_id=p_workflow WHERE job_id=item.job_id;
   n:=n+1;
  END IF;
 END LOOP;
 RETURN jsonb_build_object('released',n,'more',n=p_limit);
END $$;

-- Serialize permanent erasure with queue acknowledgements, avoiding inverse row-lock order.
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('inventory.erase_server(uuid,uuid)'::regprocedure) INTO definition;
 definition:=replace(definition,'PERFORM pg_advisory_xact_lock(909001);',
 'PERFORM pg_advisory_xact_lock(7348001);PERFORM pg_advisory_xact_lock(909001);');
 definition:=replace(definition,'WHERE w.execution_id IS NOT NULL;',
 'WHERE w.execution_id IS NOT NULL UNION SELECT DISTINCT q.execution_id AS id FROM automation.n8n_queue q
 JOIN pg_temp.server_purge_rows marked ON marked.rel=''automation.n8n_queue''::regclass AND to_jsonb(q) @> marked.key WHERE q.execution_id IS NOT NULL;');
 EXECUTE definition;
END $$;
-- Scheduled database refreshes enter the same command queue as a button click.
DO $$ DECLARE definition text; a integer; b integer; BEGIN
 SELECT pg_get_functiondef('automation.workflow_tick(text,text,text)'::regprocedure) INTO definition;
 a:=strpos(definition,'   rid:=cve.schedule_import(');
 b:=strpos(substr(definition,a),chr(10)||'  END IF;');
 IF a=0 OR b=0 THEN RAISE EXCEPTION 'unexpected scheduled import definition'; END IF;
 definition:=substr(definition,1,a-1)||
 '   INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,correlation_id,deduplication_key)
 VALUES(''command'',session_user,''cve.refresh'',jsonb_build_object(''configuration'',cfg.source_config),correlation,''scheduled-update:''||slot::text) ON CONFLICT DO NOTHING;'
 ||substr(definition,a+b-1);
 EXECUTE definition;
 SELECT pg_get_functiondef('automation.workflow_summary()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'''next_update_at'',s.next_update_at,',
 '''next_update_at'',s.next_update_at,''queue'',(SELECT jsonb_build_object(
 ''pending'',count(*) FILTER(WHERE state=''pending''),''processing'',count(*) FILTER(WHERE state=''processing''),
 ''failed'',count(*) FILTER(WHERE state=''failed''),''completed'',count(*) FILTER(WHERE state=''completed'')) FROM automation.n8n_queue),');
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00047_erasure_presentation','00048_n8n_message_queue');
END $$;
"""
