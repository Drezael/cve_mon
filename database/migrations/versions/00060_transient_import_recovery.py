"""n8n resumes transient terminal import failures without restarting a service."""

from alembic import op

revision = "00060_transient_import_recovery"
down_revision = "00059_live_status_cache"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve automatic recovery receipts and import checkpoints")


DDL = r"""
CREATE INDEX jobs_transient_recovery ON automation.jobs(job_type,created_at,id) WHERE runtime_version=1 AND status IN ('failed','timed_out');
UPDATE automation.job_types SET retry_base=15,retry_cap=120 WHERE code='cve.import.cve_list';
INSERT INTO security.technical_principals(name,status) VALUES('n8n-import-recovery','active');
CREATE TABLE automation.import_recovery_receipts (
 failed_job_id uuid PRIMARY KEY REFERENCES automation.jobs(id),
 recovery_id uuid NOT NULL UNIQUE REFERENCES automation.worker_recoveries(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),execution_id text NOT NULL
);
CREATE INDEX import_recovery_window ON automation.import_recovery_receipts(created_at DESC);
CREATE FUNCTION automation.import_recovery_tick(p_execution text,p_workflow text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET jit=off AS $$
DECLARE old automation.jobs; boot uuid; qid uuid; answer jsonb;
BEGIN
 IF session_user<>'workflow_control' OR p_workflow IS DISTINCT FROM 'cve-control-import'
 OR p_execution IS NULL OR p_execution !~ '^[A-Za-z0-9_-]{1,128}$' THEN RAISE EXCEPTION 'n8n import recovery required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(7348001);
 IF NOT EXISTS(SELECT 1 FROM automation.workflow_settings WHERE enabled AND auto_updates)
 OR (SELECT count(*) FROM automation.import_recovery_receipts WHERE created_at>clock_timestamp()-interval '1 hour')>=3 THEN RETURN 0; END IF;
 SELECT j.* INTO old FROM cve.import_runs r JOIN automation.jobs j ON j.id=r.job_id
 JOIN cve.sources source ON source.id=r.source_id AND source.enabled
 WHERE r.source_id='cve_list' ORDER BY r.created_at DESC,r.id LIMIT 1 FOR UPDATE OF j;
 IF old.id IS NULL OR old.status NOT IN ('failed','timed_out') OR old.cancel_requested
 OR old.error_code NOT IN ('NETWORK','TIMEOUT','DATABASE','RATE_LIMIT','TEMPORARY','UNAVAILABLE','SHUTDOWN','LEASE_LOST')
 OR old.finished_at>clock_timestamp()-interval '60 seconds'
 OR EXISTS(SELECT 1 FROM automation.import_recovery_receipts WHERE failed_job_id=old.id)
 OR EXISTS(SELECT 1 FROM automation.jobs WHERE replay_of=old.id)
 OR EXISTS(SELECT 1 FROM automation.workflow_runs WHERE correlation_id=old.correlation_id AND (paused OR cancelled))
 THEN RETURN 0; END IF;
 boot:=gen_random_uuid();
 INSERT INTO automation.worker_recoveries(id,handler_role,job_types) VALUES(boot,'importer',ARRAY['cve.import.cve_list']);
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,correlation_id,deduplication_key,state,workflow_id,execution_id,finished_at)
 VALUES('command','importer','worker.recover',jsonb_build_object('recovery_id',boot),boot,'worker.recover:'||boot::text,'completed',p_workflow,p_execution,clock_timestamp()) RETURNING id INTO qid;
 UPDATE automation.worker_recoveries SET queue_id=qid WHERE id=boot;
 answer:=automation.perform_worker_recovery(boot);
 UPDATE automation.n8n_queue SET result=answer WHERE id=qid;
 INSERT INTO automation.import_recovery_receipts(failed_job_id,recovery_id,execution_id) VALUES(old.id,boot,p_execution);
 INSERT INTO security.audit_log(technical_principal_id,action,object_type,object_id,outcome,metadata)
 SELECT id,'workflow.import.recovery','job',old.id::text,'success',jsonb_build_object('replayed',answer->'replayed','error_code',old.error_code) FROM security.technical_principals WHERE name='n8n-import-recovery';
 RETURN coalesce((answer->>'replayed')::integer,0);
END $$;
REVOKE ALL ON FUNCTION automation.import_recovery_tick(text,text) FROM PUBLIC;
-- Only the validated central tick calls the private helper.
ALTER FUNCTION automation.workflow_tick(text,text,text) RENAME TO workflow_tick_v59;
REVOKE ALL ON FUNCTION automation.workflow_tick_v59(text,text,text) FROM workflow_control;
CREATE FUNCTION automation.workflow_tick(p_stage text,p_execution text,p_workflow text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE recovered integer:=0; answer jsonb;
BEGIN
 IF session_user<>'workflow_control' OR p_workflow IS DISTINCT FROM 'cve-control-'||p_stage
 OR p_execution IS NULL OR p_execution !~ '^[A-Za-z0-9_-]{1,128}$' THEN RAISE EXCEPTION 'n8n tick required' USING ERRCODE='42501'; END IF;
 IF p_stage='import' THEN recovered:=automation.import_recovery_tick(p_execution,p_workflow); END IF;
 answer:=automation.workflow_tick_v59(p_stage,p_execution,p_workflow);
 RETURN answer||jsonb_build_object('recovered',recovered);
END $$;
REVOKE ALL ON FUNCTION automation.workflow_tick(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.workflow_tick(text,text,text) TO workflow_control;
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00059_live_status_cache','00060_transient_import_recovery');
END $$;
"""
