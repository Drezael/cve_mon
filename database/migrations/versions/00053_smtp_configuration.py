"""Administrator SMTP configuration; encrypted secrets and n8n-authorized application."""

from alembic import op

revision = "00053_smtp_configuration"
down_revision = "00052_audit_usernames"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve SMTP configuration versions and receipts")


DDL = r"""
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable)
 VALUES('notification:smtp:manage','Configure central SMTP transport','human',true,NULL,false,false);
INSERT INTO security.role_permissions(role_id,permission_code) SELECT id,'notification:smtp:manage' FROM security.roles WHERE code='admin';
INSERT INTO security.technical_principals(name,status) VALUES('smtp-configuration-service','active');
CREATE TABLE automation.smtp_configs (
 id uuid PRIMARY KEY, version bigint NOT NULL UNIQUE, configuration jsonb NOT NULL CHECK(jsonb_typeof(configuration)='object' AND configuration ?& ARRAY['enabled','host','port','sender','recipients'] AND configuration-ARRAY['enabled','host','port','sender','recipients']='{}'::jsonb),
 credentials bytea NOT NULL CHECK(octet_length(credentials)>28), key_id text NOT NULL,
 requested_by uuid NOT NULL REFERENCES security.users(id), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 queue_id uuid UNIQUE REFERENCES automation.n8n_queue(id), state text NOT NULL DEFAULT 'waiting' CHECK(state IN ('waiting','authorized','applying','applied','failed','cancelled')),
 execution_id text,started_at timestamptz,finished_at timestamptz,error_code text,lease_token uuid,lease_until timestamptz
);
CREATE UNIQUE INDEX smtp_single_active ON automation.smtp_configs((true)) WHERE state IN ('waiting','authorized','applying');
GRANT SELECT ON automation.smtp_configs TO api_security,dashboard_admin;
CREATE FUNCTION automation.request_smtp(p_id uuid,p_actor uuid,p_version bigint,p_config jsonb,p_key text,p_credentials bytea) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE previous bigint; old automation.smtp_configs; q uuid; BEGIN
 IF session_user<>'api_security' OR NOT EXISTS(SELECT 1 FROM security.users u JOIN security.user_roles ur ON ur.user_id=u.id JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE u.id=p_actor AND u.status='active' AND rp.permission_code='notification:smtp:manage') THEN RAISE EXCEPTION 'SMTP configuration denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(7353001);
 SELECT * INTO old FROM automation.smtp_configs WHERE id=p_id;
 IF old.id IS NOT NULL THEN
  IF old.requested_by<>p_actor OR old.configuration<>p_config OR old.credentials<>p_credentials THEN RAISE EXCEPTION 'request conflict' USING ERRCODE='23505'; END IF;
  RETURN old.id;
 END IF;
 SELECT coalesce(max(version),0) INTO previous FROM automation.smtp_configs;
 IF p_version<>previous THEN RAISE EXCEPTION 'configuration version conflict' USING ERRCODE='40001'; END IF;
 INSERT INTO automation.smtp_configs(id,version,configuration,credentials,key_id,requested_by) VALUES(p_id,previous+1,p_config,p_credentials,p_key,p_actor);
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,actor_id,correlation_id,deduplication_key)
 VALUES('command',session_user,'smtp.configure',jsonb_build_object('configuration_id',p_id,'version',previous+1),p_actor,p_id,'smtp.configure:'||p_id::text) RETURNING id INTO q;
 UPDATE automation.smtp_configs SET queue_id=q WHERE id=p_id;
 INSERT INTO security.audit_log(actor_user_id,action,object_type,object_id,outcome,metadata) VALUES(p_actor,'smtp.configuration.requested','smtp_configuration',p_id::text,'success',jsonb_build_object('version',previous+1));
 RETURN p_id;
END $$;
REVOKE ALL ON FUNCTION automation.request_smtp(uuid,uuid,bigint,jsonb,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.request_smtp(uuid,uuid,bigint,jsonb,text,bytea) TO api_security;
ALTER FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) RENAME TO n8n_decide_v52;
REVOKE ALL ON FUNCTION automation.n8n_decide_v52(uuid,uuid,text,text,text) FROM workflow_control;
CREATE FUNCTION automation.n8n_decide(p_id uuid,p_token uuid,p_kind text,p_execution text,p_workflow text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q automation.n8n_queue; cfg automation.smtp_configs; permitted boolean; BEGIN
 PERFORM pg_advisory_xact_lock(7348001);
 SELECT * INTO q FROM automation.n8n_queue WHERE id=p_id FOR UPDATE;
 IF q.kind IS DISTINCT FROM 'command' OR q.message_type IS DISTINCT FROM 'smtp.configure' THEN RETURN automation.n8n_decide_v52(p_id,p_token,p_kind,p_execution,p_workflow); END IF;
 IF session_user<>'workflow_control' OR p_workflow<>'cve-control-queue' THEN RAISE EXCEPTION 'n8n required' USING ERRCODE='42501'; END IF;
 IF q.state='completed' AND q.execution_id=p_execution AND q.workflow_id=p_workflow THEN RETURN jsonb_build_object('processed',true,'id',p_id); END IF;
 IF q.state<>'processing' OR p_kind<>'command' OR q.lease_token IS DISTINCT FROM p_token OR q.execution_id IS DISTINCT FROM p_execution OR q.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'stale queue receipt' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT cfg FROM automation.smtp_configs WHERE queue_id=p_id FOR UPDATE;
 SELECT EXISTS(SELECT 1 FROM security.users u JOIN security.user_roles ur ON ur.user_id=u.id JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE u.id=cfg.requested_by AND u.status='active' AND rp.permission_code='notification:smtp:manage') INTO permitted;
 UPDATE automation.smtp_configs SET state=CASE WHEN permitted THEN 'authorized' ELSE 'cancelled' END,execution_id=p_execution,error_code=CASE WHEN permitted THEN NULL ELSE 'REQUESTER_UNAVAILABLE' END WHERE id=cfg.id;
 UPDATE automation.n8n_queue SET state=CASE WHEN permitted THEN 'completed' ELSE 'cancelled' END,finished_at=clock_timestamp(),lease_token=NULL,lease_until=NULL,result=jsonb_build_object('configuration_id',cfg.id,'authorized',permitted) WHERE id=p_id;
 RETURN jsonb_build_object('processed',true,'id',p_id);
END $$;
REVOKE ALL ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) TO workflow_control;
CREATE FUNCTION automation.claim_smtp() RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE cfg automation.smtp_configs; BEGIN
 IF session_user<>'dashboard_admin' THEN RAISE EXCEPTION 'host controller required' USING ERRCODE='42501'; END IF;
 SELECT c.* INTO cfg FROM automation.smtp_configs c JOIN automation.n8n_queue q ON q.id=c.queue_id WHERE q.state='completed' AND q.finished_at<clock_timestamp()-interval '2 seconds' AND (c.state='authorized' OR (c.state='applying' AND c.lease_until<clock_timestamp())) ORDER BY c.version LIMIT 1 FOR UPDATE OF c SKIP LOCKED;
 IF cfg.id IS NULL THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM security.users u JOIN security.user_roles ur ON ur.user_id=u.id JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE u.id=cfg.requested_by AND u.status='active' AND rp.permission_code='notification:smtp:manage') THEN
  UPDATE automation.smtp_configs SET state='cancelled',finished_at=clock_timestamp(),error_code='REQUESTER_UNAVAILABLE' WHERE id=cfg.id;
  INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,correlation_id,deduplication_key) VALUES('result',session_user,'smtp.configure',jsonb_build_object('configuration_id',cfg.id,'status','cancelled'),cfg.id,'smtp.configure.result:'||cfg.id::text) ON CONFLICT DO NOTHING;
  RETURN NULL;
 END IF;
 UPDATE automation.smtp_configs SET state='applying',started_at=clock_timestamp(),lease_token=gen_random_uuid(),lease_until=clock_timestamp()+interval '120 seconds' WHERE id=cfg.id;
 RETURN cfg.id;
END $$;
CREATE FUNCTION automation.finish_smtp(p_id uuid,p_token uuid,p_error text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE cfg automation.smtp_configs; BEGIN
 IF session_user<>'dashboard_admin' THEN RAISE EXCEPTION 'host controller required' USING ERRCODE='42501'; END IF;
 SELECT * INTO cfg FROM automation.smtp_configs WHERE id=p_id FOR UPDATE;
 IF cfg.state IS DISTINCT FROM 'applying' OR cfg.lease_token IS DISTINCT FROM p_token OR cfg.lease_until<clock_timestamp() THEN RAISE EXCEPTION 'stale SMTP receipt' USING ERRCODE='42501'; END IF;
 IF p_error IS NOT NULL AND p_error NOT IN ('SMTP_CONFIGURATION_FAILED','SMTP_HOST_NOT_ALLOWED') THEN RAISE EXCEPTION 'invalid failure'; END IF;
 UPDATE automation.smtp_configs SET state=CASE WHEN p_error IS NULL THEN 'applied' ELSE 'failed' END,finished_at=clock_timestamp(),error_code=p_error,lease_token=NULL,lease_until=NULL WHERE id=p_id;
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,correlation_id,deduplication_key)
 VALUES('result',session_user,'smtp.configure',jsonb_build_object('configuration_id',p_id,'status',CASE WHEN p_error IS NULL THEN 'applied' ELSE 'failed' END,'error_code',p_error),p_id,'smtp.configure.result:'||p_id::text) ON CONFLICT DO NOTHING;
 INSERT INTO security.audit_log(technical_principal_id,action,object_type,object_id,outcome,metadata) SELECT id,'smtp.configuration.finished','smtp_configuration',p_id::text,CASE WHEN p_error IS NULL THEN 'success' ELSE 'failure' END,jsonb_build_object('version',cfg.version,'error_code',p_error) FROM security.technical_principals WHERE name='smtp-configuration-service';
END $$;
REVOKE ALL ON FUNCTION automation.claim_smtp(),automation.finish_smtp(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.claim_smtp(),automation.finish_smtp(uuid,uuid,text) TO dashboard_admin;
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00052_audit_usernames','00053_smtp_configuration');
END $$;
"""
