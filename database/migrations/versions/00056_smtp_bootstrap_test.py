"""First-start SMTP defaults and durable n8n-authorized test mail."""

from alembic import op

revision = "00056_smtp_bootstrap_test"
down_revision = "00055_direct_outbound"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve SMTP settings and test receipts")


DDL = r"""
ALTER TABLE automation.smtp_configs ALTER COLUMN requested_by DROP NOT NULL;
ALTER TABLE automation.smtp_configs ADD COLUMN origin text NOT NULL DEFAULT 'user' CHECK(origin IN ('user','environment'));
ALTER TABLE automation.smtp_configs ADD CHECK(requested_by IS NOT NULL OR (origin='environment' AND owner_id IS NULL));
CREATE FUNCTION automation.bootstrap_smtp(p_id uuid,p_config jsonb,p_key text,p_credentials bytea) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q uuid; existing uuid; BEGIN
 IF session_user<>'api_security' THEN RAISE EXCEPTION 'API startup required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(7353001);
 SELECT id INTO existing FROM automation.smtp_configs WHERE owner_id IS NULL ORDER BY version DESC LIMIT 1;
 IF existing IS NOT NULL THEN RETURN existing; END IF;
 INSERT INTO automation.smtp_configs(id,version,configuration,credentials,key_id,origin) VALUES(p_id,1,p_config,p_credentials,p_key,'environment');
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,correlation_id,deduplication_key)
 VALUES('command','smtp-configuration-service','smtp.configure',jsonb_build_object('configuration_id',p_id,'version',1),p_id,'smtp.configure:'||p_id::text) RETURNING id INTO q;
 UPDATE automation.smtp_configs SET queue_id=q WHERE id=p_id;
 INSERT INTO security.audit_log(technical_principal_id,action,object_type,object_id,outcome,metadata) SELECT id,'smtp.configuration.requested','smtp_configuration',p_id::text,'success','{"origin":"environment","version":1}'::jsonb FROM security.technical_principals WHERE name='smtp-configuration-service';
 RETURN p_id;
END $$;
REVOKE ALL ON FUNCTION automation.bootstrap_smtp(uuid,jsonb,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.bootstrap_smtp(uuid,jsonb,text,bytea) TO api_security;
DO $$ DECLARE d text; old text := 'automation.smtp_permitted(cfg.requested_by,cfg.owner_id)'; BEGIN
 SELECT pg_get_functiondef('automation.n8n_decide(uuid,uuid,text,text,text)'::regprocedure) INTO d;
 IF position(old IN d)=0 THEN RAISE EXCEPTION 'SMTP decision migration mismatch'; END IF;
 EXECUTE replace(d,old,'((cfg.origin=''environment'' AND cfg.requested_by IS NULL AND cfg.owner_id IS NULL) OR automation.smtp_permitted(cfg.requested_by,cfg.owner_id))');
 SELECT pg_get_functiondef('automation.claim_smtp()'::regprocedure) INTO d;
 IF position(old IN d)=0 THEN RAISE EXCEPTION 'SMTP claim migration mismatch'; END IF;
 EXECUTE replace(d,old,'((cfg.origin=''environment'' AND cfg.requested_by IS NULL AND cfg.owner_id IS NULL) OR automation.smtp_permitted(cfg.requested_by,cfg.owner_id))');
END $$;
CREATE TABLE automation.smtp_tests (
 id uuid PRIMARY KEY, requested_by uuid NOT NULL REFERENCES security.users(id) ON DELETE CASCADE,
 owner_id uuid REFERENCES security.users(id) ON DELETE CASCADE,
 configuration_id uuid NOT NULL REFERENCES automation.smtp_configs(id) ON DELETE CASCADE,
 recipients jsonb NOT NULL CHECK(jsonb_typeof(recipients)='array' AND jsonb_array_length(recipients) BETWEEN 1 AND 20),
 queue_id uuid UNIQUE REFERENCES automation.n8n_queue(id),
 state text NOT NULL DEFAULT 'waiting' CHECK(state IN ('waiting','authorized','running','sent','failed','cancelled')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),finished_at timestamptz,
 execution_id text,lease_token uuid,lease_until timestamptz,error_code text
);
GRANT SELECT ON automation.smtp_tests TO api_security,dashboard_admin;
CREATE FUNCTION automation.request_smtp_test(p_id uuid,p_actor uuid,p_owner uuid,p_config uuid,p_recipients jsonb) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing automation.smtp_tests; q uuid; BEGIN
 IF session_user<>'api_security' OR NOT automation.smtp_permitted(p_actor,p_owner) THEN RAISE EXCEPTION 'SMTP test denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(7353002);
 SELECT * INTO existing FROM automation.smtp_tests WHERE id=p_id;
 IF existing.id IS NOT NULL THEN
  IF existing.requested_by<>p_actor OR existing.owner_id IS DISTINCT FROM p_owner OR existing.configuration_id<>p_config OR existing.recipients<>p_recipients THEN RAISE EXCEPTION 'test request conflict' USING ERRCODE='23505'; END IF;
  RETURN p_id;
 END IF;
 IF (SELECT count(*) FROM automation.smtp_tests WHERE requested_by=p_actor AND created_at>clock_timestamp()-interval '5 minutes')>=5 THEN RAISE EXCEPTION 'test rate exceeded' USING ERRCODE='54000'; END IF;
 IF NOT EXISTS(SELECT 1 FROM automation.smtp_configs WHERE id=p_config AND state='applied' AND configuration->>'enabled'='true' AND (owner_id IS NULL OR owner_id=p_owner)) THEN RAISE EXCEPTION 'applied SMTP required' USING ERRCODE='42501'; END IF;
 INSERT INTO automation.smtp_tests(id,requested_by,owner_id,configuration_id,recipients) VALUES(p_id,p_actor,p_owner,p_config,p_recipients);
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,actor_id,correlation_id,deduplication_key) VALUES('command',session_user,'smtp.test',jsonb_build_object('test_id',p_id),p_actor,p_id,'smtp.test:'||p_id::text) RETURNING id INTO q;
 UPDATE automation.smtp_tests SET queue_id=q WHERE id=p_id;
 INSERT INTO security.audit_log(actor_user_id,action,object_type,object_id,outcome,metadata) VALUES(p_actor,'smtp.test.requested','smtp_test',p_id::text,'success','{}');
 RETURN p_id;
END $$;
REVOKE ALL ON FUNCTION automation.request_smtp_test(uuid,uuid,uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.request_smtp_test(uuid,uuid,uuid,uuid,jsonb) TO api_security;
ALTER FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) RENAME TO n8n_decide_v55;
REVOKE ALL ON FUNCTION automation.n8n_decide_v55(uuid,uuid,text,text,text) FROM workflow_control;
CREATE FUNCTION automation.n8n_decide(p_id uuid,p_token uuid,p_kind text,p_execution text,p_workflow text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q automation.n8n_queue; t automation.smtp_tests; permitted boolean; BEGIN
 PERFORM pg_advisory_xact_lock(7348001);
 SELECT * INTO q FROM automation.n8n_queue WHERE id=p_id FOR UPDATE;
 IF q.kind IS DISTINCT FROM 'command' OR q.message_type IS DISTINCT FROM 'smtp.test' THEN RETURN automation.n8n_decide_v55(p_id,p_token,p_kind,p_execution,p_workflow); END IF;
 IF session_user<>'workflow_control' OR p_workflow<>'cve-control-queue' THEN RAISE EXCEPTION 'n8n required' USING ERRCODE='42501'; END IF;
 IF q.state='completed' AND q.execution_id=p_execution AND q.workflow_id=p_workflow THEN RETURN jsonb_build_object('processed',true,'id',p_id); END IF;
 IF q.state<>'processing' OR p_kind<>'command' OR q.lease_token IS DISTINCT FROM p_token OR q.execution_id IS DISTINCT FROM p_execution OR q.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'stale queue receipt' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT t FROM automation.smtp_tests WHERE queue_id=p_id FOR UPDATE;
 permitted:=automation.smtp_permitted(t.requested_by,t.owner_id);
 UPDATE automation.smtp_tests SET state=CASE WHEN permitted THEN 'authorized' ELSE 'cancelled' END,execution_id=p_execution,finished_at=CASE WHEN permitted THEN NULL ELSE clock_timestamp() END,error_code=CASE WHEN permitted THEN NULL ELSE 'REQUESTER_UNAVAILABLE' END WHERE id=t.id;
 UPDATE automation.n8n_queue SET state=CASE WHEN permitted THEN 'completed' ELSE 'cancelled' END,finished_at=clock_timestamp(),lease_token=NULL,lease_until=NULL,result=jsonb_build_object('test_id',t.id,'authorized',permitted) WHERE id=p_id;
 RETURN jsonb_build_object('processed',true,'id',p_id);
END $$;
REVOKE ALL ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) TO workflow_control;
CREATE FUNCTION automation.finish_smtp_test(p_id uuid,p_token uuid,p_error text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE t automation.smtp_tests; BEGIN
 IF session_user<>'dashboard_admin' THEN RAISE EXCEPTION 'host controller required' USING ERRCODE='42501'; END IF;
 SELECT * INTO t FROM automation.smtp_tests WHERE id=p_id FOR UPDATE;
 IF t.state IS DISTINCT FROM 'running' OR t.lease_token IS DISTINCT FROM p_token THEN RAISE EXCEPTION 'stale test receipt' USING ERRCODE='42501'; END IF;
 IF p_error IS NOT NULL AND p_error NOT IN ('SMTP_AUTHENTICATION_FAILED','SMTP_TLS_FAILED','SMTP_CONNECTION_FAILED','SMTP_REJECTED','SMTP_SETTINGS_CHANGED','SMTP_OUTCOME_UNKNOWN') THEN RAISE EXCEPTION 'invalid test error'; END IF;
 UPDATE automation.smtp_tests SET state=CASE WHEN p_error IS NULL THEN 'sent' ELSE 'failed' END,finished_at=clock_timestamp(),error_code=p_error,lease_token=NULL,lease_until=NULL WHERE id=p_id;
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,correlation_id,deduplication_key) VALUES('result','smtp-configuration-service','smtp.test',jsonb_build_object('test_id',p_id,'status',CASE WHEN p_error IS NULL THEN 'sent' ELSE 'failed' END,'error_code',p_error),p_id,'smtp.test.result:'||p_id::text) ON CONFLICT DO NOTHING;
 INSERT INTO security.audit_log(technical_principal_id,action,object_type,object_id,outcome,metadata) SELECT id,'smtp.test.finished','smtp_test',p_id::text,CASE WHEN p_error IS NULL THEN 'success' ELSE 'failure' END,jsonb_build_object('error_code',p_error) FROM security.technical_principals WHERE name='smtp-configuration-service';
END $$;
CREATE FUNCTION automation.claim_smtp_test() RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE t automation.smtp_tests; expired automation.smtp_tests; BEGIN
 IF session_user<>'dashboard_admin' THEN RAISE EXCEPTION 'host controller required' USING ERRCODE='42501'; END IF;
 FOR expired IN SELECT * FROM automation.smtp_tests WHERE state='running' AND lease_until<clock_timestamp() FOR UPDATE SKIP LOCKED LOOP
  PERFORM automation.finish_smtp_test(expired.id,expired.lease_token,'SMTP_OUTCOME_UNKNOWN');
 END LOOP;
 SELECT * INTO t FROM automation.smtp_tests WHERE state='authorized' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED;
 IF t.id IS NULL THEN RETURN NULL; END IF;
 UPDATE automation.smtp_tests SET state='running',lease_token=gen_random_uuid(),lease_until=clock_timestamp()+interval '120 seconds' WHERE id=t.id RETURNING * INTO t;
 IF NOT automation.smtp_permitted(t.requested_by,t.owner_id) THEN
  PERFORM automation.finish_smtp_test(t.id,t.lease_token,'SMTP_SETTINGS_CHANGED');
  RETURN NULL;
 END IF;
 RETURN t.id;
END $$;
REVOKE ALL ON FUNCTION automation.claim_smtp_test(),automation.finish_smtp_test(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.claim_smtp_test(),automation.finish_smtp_test(uuid,uuid,text) TO dashboard_admin;
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00055_direct_outbound','00056_smtp_bootstrap_test');
END $$;
"""
