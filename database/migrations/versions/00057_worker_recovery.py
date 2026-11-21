"""Durable worker recovery, fenced diagnostics and truthful recovered-job status."""

from alembic import op

revision = "00057_worker_recovery"
down_revision = "00056_smtp_bootstrap_test"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve recovery receipts and failed-task diagnostics")


DDL = r"""
CREATE INDEX IF NOT EXISTS jobs_replay_parent ON automation.jobs(replay_of) WHERE replay_of IS NOT NULL;
CREATE INDEX IF NOT EXISTS jobs_success_type_time ON automation.jobs(job_type,finished_at DESC) WHERE runtime_version=1 AND status='succeeded';
ALTER TABLE automation.jobs ADD COLUMN diagnostic_code text CHECK(diagnostic_code ~ '^[A-Z][A-Z0-9_]{0,63}$');
ALTER TABLE automation.job_attempts ADD COLUMN diagnostic_code text CHECK(diagnostic_code ~ '^[A-Z][A-Z0-9_]{0,63}$');
ALTER TABLE automation.job_attempts ADD COLUMN error_class text CHECK(error_class ~ '^[A-Za-z][A-Za-z0-9_]{0,63}$');
CREATE FUNCTION automation.diagnose_job(p_id uuid,p_worker uuid,p_token uuid,p_epoch bigint,p_code text,p_class text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF p_code IS NULL OR p_class IS NULL OR p_code !~ '^[A-Z][A-Z0-9_]{0,63}$' OR p_class !~ '^[A-Za-z][A-Za-z0-9_]{0,63}$' THEN RAISE EXCEPTION 'invalid diagnostic'; END IF;
 IF NOT automation.check_job_fence(p_id,p_worker,p_token,p_epoch) THEN RETURN false; END IF;
 UPDATE automation.jobs SET diagnostic_code=p_code WHERE id=p_id;
 UPDATE automation.job_attempts SET diagnostic_code=p_code,error_class=p_class WHERE job_id=p_id AND fencing_token=p_epoch;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION automation.diagnose_job(uuid,uuid,uuid,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.diagnose_job(uuid,uuid,uuid,bigint,text,text) TO importer,enricher,inventory_processor,matcher,findings_writer,notification,status_probe,ansible_worker;

CREATE TABLE automation.worker_recoveries (
 id uuid PRIMARY KEY,handler_role name NOT NULL,job_types text[] NOT NULL,
 queue_id uuid UNIQUE REFERENCES automation.n8n_queue(id),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 finished_at timestamptz,result jsonb
);
CREATE FUNCTION automation.request_worker_recovery(p_id uuid,p_types text[]) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE known text[]; old automation.worker_recoveries; q uuid; BEGIN
 SELECT array_agg(code ORDER BY code) INTO known FROM automation.job_types WHERE handler_role=session_user AND code=ANY(p_types);
 IF p_id IS NULL OR coalesce(cardinality(p_types),0) NOT BETWEEN 1 AND 64 OR coalesce(cardinality(known),0)<>cardinality(p_types) THEN RAISE EXCEPTION 'worker recovery scope denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO old FROM automation.worker_recoveries WHERE id=p_id;
 IF old.id IS NOT NULL THEN
  IF old.handler_role<>session_user OR old.job_types<>known THEN RAISE EXCEPTION 'recovery identity conflict'; END IF;
  RETURN p_id;
 END IF;
 INSERT INTO automation.worker_recoveries(id,handler_role,job_types) VALUES(p_id,session_user,known);
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,correlation_id,deduplication_key)
 VALUES('command',session_user,'worker.recover',jsonb_build_object('recovery_id',p_id),p_id,'worker.recover:'||p_id::text) RETURNING id INTO q;
 UPDATE automation.worker_recoveries SET queue_id=q WHERE id=p_id;
 RETURN p_id;
END $$;
REVOKE ALL ON FUNCTION automation.request_worker_recovery(uuid,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.request_worker_recovery(uuid,text[]) TO importer,enricher,inventory_processor,matcher,findings_writer,notification,status_probe,ansible_worker;

-- Keep failed attempts and checkpoints, synchronizing the business run with its job.
CREATE FUNCTION cve.sync_import_job_state() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.job_type NOT LIKE 'cve.import.%' OR OLD.status IS NOT DISTINCT FROM NEW.status THEN RETURN NEW; END IF;
 UPDATE cve.import_runs SET status=CASE WHEN NEW.status='running' THEN 'running' WHEN NEW.status IN ('pending','queued','retry_pending') THEN 'planned' WHEN NEW.status='cancelled' THEN 'cancelled' ELSE 'failed' END,
 finished_at=CASE WHEN NEW.status IN ('failed','timed_out','cancelled') THEN NEW.finished_at ELSE NULL END
 WHERE job_id=NEW.id AND status NOT IN ('completed','partial') AND NEW.status<>'succeeded';
 RETURN NEW;
END $$;
CREATE TRIGGER importer_job_state AFTER UPDATE OF status ON automation.jobs FOR EACH ROW EXECUTE FUNCTION cve.sync_import_job_state();
UPDATE cve.import_runs r SET status=CASE WHEN j.status='cancelled' THEN 'cancelled' ELSE 'failed' END,finished_at=j.finished_at
FROM automation.jobs j WHERE r.job_id=j.id AND r.status IN ('planned','running') AND j.status IN ('failed','timed_out','cancelled');

CREATE FUNCTION automation.perform_worker_recovery(p_id uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE boot automation.worker_recoveries; old automation.jobs; created uuid; replayed integer:=0; run cve.import_runs; occupied uuid; continuation uuid; continuation_queue uuid; BEGIN
 IF session_user<>'workflow_control' THEN RAISE EXCEPTION 'n8n recovery required' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT boot FROM automation.worker_recoveries WHERE id=p_id FOR UPDATE;
 IF boot.finished_at IS NOT NULL THEN RETURN boot.result; END IF;
 -- The central controller may replay only the handler-owned types in this receipt.
 UPDATE automation.job_types SET producer_roles=array_append(producer_roles,'workflow_control'::name)
 WHERE code=ANY(boot.job_types) AND handler_role=boot.handler_role AND NOT 'workflow_control'::name=ANY(producer_roles);
 FOR old IN SELECT j.* FROM automation.jobs j JOIN automation.job_types t ON t.code=j.job_type
 WHERE j.runtime_version=1 AND j.job_type=ANY(boot.job_types) AND t.handler_role=boot.handler_role
 AND j.status IN ('failed','timed_out') AND j.error_code IN ('TEMPORARY','NETWORK','DATABASE','TIMEOUT','RATE_LIMIT','UNAVAILABLE','SHUTDOWN','LEASE_LOST')
 AND (j.job_type NOT IN ('status.collect','findings.maintenance','notifications.maintenance') OR NOT EXISTS(SELECT 1 FROM automation.jobs newer WHERE newer.job_type=j.job_type AND newer.created_at>j.created_at))
 AND NOT j.cancel_requested AND NOT EXISTS(SELECT 1 FROM automation.jobs child WHERE child.replay_of=j.id)
 AND NOT EXISTS(SELECT 1 FROM automation.workflow_runs w WHERE w.correlation_id=j.correlation_id AND (w.paused OR w.cancelled))
 AND (j.job_type NOT LIKE 'cve.import.%' OR EXISTS(
  SELECT 1 FROM cve.import_runs r JOIN cve.sources source ON source.id=r.source_id AND source.enabled WHERE r.job_id=j.id AND NOT EXISTS(SELECT 1 FROM cve.import_runs newer WHERE newer.source_id=r.source_id AND newer.created_at>r.created_at)))
 ORDER BY j.created_at,j.id LIMIT 256 FOR UPDATE OF j SKIP LOCKED LOOP
  IF old.job_type LIKE 'cve.import.%' THEN
   SELECT * INTO run FROM cve.import_runs WHERE job_id=old.id FOR UPDATE;
   IF run.id IS NULL THEN CONTINUE; END IF;
   SELECT active_run INTO occupied FROM cve.source_leases WHERE source_id=run.source_id FOR UPDATE;
   IF occupied IS NOT NULL AND occupied<>run.id AND EXISTS(SELECT 1 FROM cve.import_runs r JOIN automation.jobs j ON j.id=r.job_id WHERE r.id=occupied AND j.status IN ('pending','queued','running','retry_pending')) THEN CONTINUE; END IF;
  END IF;
  SELECT id INTO created FROM automation.enqueue_job(old.job_type,old.payload_version,old.payload,'worker-recovery:'||old.id::text,
   old.correlation_id,old.priority,NULL,NULL,old.max_attempts,'worker-recovery',false,old.id);
  IF old.job_type LIKE 'cve.import.%' THEN
   UPDATE cve.import_runs SET job_id=created,status='planned',finished_at=NULL WHERE id=run.id;
   UPDATE cve.source_leases SET active_run=run.id WHERE source_id=run.source_id;
  END IF;
  replayed:=replayed+1;
 END LOOP;
 IF replayed=256 THEN
  continuation:=gen_random_uuid();
  INSERT INTO automation.worker_recoveries(id,handler_role,job_types) VALUES(continuation,boot.handler_role,boot.job_types);
  INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,correlation_id,deduplication_key)
  VALUES('command',boot.handler_role,'worker.recover',jsonb_build_object('recovery_id',continuation),continuation,'worker.recover:'||continuation::text) RETURNING id INTO continuation_queue;
  UPDATE automation.worker_recoveries SET queue_id=continuation_queue WHERE id=continuation;
 END IF;
 UPDATE automation.worker_recoveries SET finished_at=clock_timestamp(),result=jsonb_build_object('replayed',replayed) WHERE id=p_id;
 RETURN jsonb_build_object('replayed',replayed);
END $$;
REVOKE ALL ON FUNCTION automation.perform_worker_recovery(uuid) FROM PUBLIC;

ALTER FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) RENAME TO n8n_decide_v56;
REVOKE ALL ON FUNCTION automation.n8n_decide_v56(uuid,uuid,text,text,text) FROM workflow_control;
CREATE FUNCTION automation.n8n_decide(p_id uuid,p_token uuid,p_kind text,p_execution text,p_workflow text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q automation.n8n_queue; boot automation.worker_recoveries; recovered_result jsonb; BEGIN
 PERFORM pg_advisory_xact_lock(7348001);
 SELECT * INTO q FROM automation.n8n_queue WHERE id=p_id FOR UPDATE;
 IF q.kind IS DISTINCT FROM 'command' OR q.message_type IS DISTINCT FROM 'worker.recover' THEN RETURN automation.n8n_decide_v56(p_id,p_token,p_kind,p_execution,p_workflow); END IF;
 IF session_user<>'workflow_control' OR p_workflow<>'cve-control-queue' THEN RAISE EXCEPTION 'n8n required' USING ERRCODE='42501'; END IF;
 IF q.state='completed' AND q.execution_id=p_execution AND q.workflow_id=p_workflow THEN RETURN jsonb_build_object('processed',true,'id',p_id); END IF;
 IF q.state<>'processing' OR p_kind<>'command' OR q.lease_token IS DISTINCT FROM p_token OR q.execution_id IS DISTINCT FROM p_execution OR q.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'stale recovery receipt' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT boot FROM automation.worker_recoveries WHERE queue_id=p_id;
 IF boot.handler_role<>q.producer THEN RAISE EXCEPTION 'recovery producer mismatch'; END IF;
 recovered_result:=automation.perform_worker_recovery(boot.id);
 UPDATE automation.n8n_queue SET state='completed',finished_at=clock_timestamp(),lease_token=NULL,lease_until=NULL,result=recovered_result WHERE id=p_id;
 RETURN jsonb_build_object('processed',true,'id',p_id);
END $$;
REVOKE ALL ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) TO workflow_control;

CREATE FUNCTION automation.job_failure_unresolved(p_id uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT NOT EXISTS(WITH RECURSIVE descendants AS (
  SELECT id,status FROM automation.jobs WHERE replay_of=p_id UNION ALL
  SELECT j.id,j.status FROM automation.jobs j JOIN descendants d ON j.replay_of=d.id
 ) SELECT 1 FROM descendants WHERE status IN ('pending','queued','running','retry_pending','succeeded'))
 AND NOT EXISTS(SELECT 1 FROM automation.jobs old JOIN automation.jobs recovered ON recovered.job_type=old.job_type
  WHERE old.id=p_id AND (old.job_type LIKE 'cve.import.%' OR old.job_type IN ('status.collect','findings.maintenance','notifications.maintenance')) AND recovered.status='succeeded' AND recovered.finished_at>old.finished_at)
$$;
REVOKE ALL ON FUNCTION automation.job_failure_unresolved(uuid) FROM PUBLIC;
DO $$ DECLARE d text; old text := 'SELECT job_type,status,finished_at FROM automation.jobs WHERE runtime_version=1 AND finished_at>clock_timestamp()-interval ''24 hours'''; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 IF position(old IN d)=0 THEN RAISE EXCEPTION 'status recovery migration mismatch'; END IF;
 d:=replace(d,old,old||' AND (status NOT IN (''failed'',''timed_out'') OR automation.job_failure_unresolved(id))');
 EXECUTE replace(d,'00056_smtp_bootstrap_test','00057_worker_recovery');
END $$;
"""
