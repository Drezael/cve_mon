"""Observe the central consumer and authorize scoped process restarts through its FIFO."""

from alembic import op

revision = "00049_control_status_restart"
down_revision = "00048_n8n_message_queue"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve restart authorization and execution receipts")


DDL = r"""
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable)
VALUES('deployment:service:restart','Restart an application microservice through n8n','human',true,NULL,false,false);
INSERT INTO security.role_permissions(role_id,permission_code) SELECT id,'deployment:service:restart' FROM security.roles WHERE code='admin';
GRANT USAGE ON SCHEMA status TO dashboard_admin;
GRANT UPDATE(name,dependencies,critical) ON status.entities TO status_probe;
CREATE TABLE automation.n8n_consumer (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), seen_at timestamptz NOT NULL,
 execution_id text NOT NULL, workflow_id text NOT NULL
);
CREATE FUNCTION automation.n8n_touch(p_execution text,p_workflow text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'workflow_control' OR p_workflow<>'cve-control-queue' OR p_execution !~ '^[A-Za-z0-9_-]{1,128}$' THEN RAISE EXCEPTION 'queue identity required' USING ERRCODE='42501'; END IF;
 INSERT INTO automation.n8n_consumer VALUES(true,clock_timestamp(),p_execution,p_workflow)
 ON CONFLICT(singleton) DO UPDATE SET seen_at=EXCLUDED.seen_at,execution_id=EXCLUDED.execution_id,workflow_id=EXCLUDED.workflow_id;
END $$;
REVOKE ALL ON FUNCTION automation.n8n_touch(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.n8n_touch(text,text) TO workflow_control;
CREATE TABLE status.service_restarts (
 id uuid PRIMARY KEY, queue_id uuid NOT NULL UNIQUE REFERENCES automation.n8n_queue(id),
 service_id text NOT NULL CHECK(service_id IN ('api','inventory','importer','enricher','matcher','findings','notification','dispatcher','ansible')),
 actor_id uuid NOT NULL REFERENCES security.users(id), reason text NOT NULL CHECK(length(reason) BETWEEN 3 AND 256),
 state text NOT NULL DEFAULT 'waiting' CHECK(state IN ('waiting','authorized','running','succeeded','failed','cancelled')),
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp(), authorized_at timestamptz, started_at timestamptz, finished_at timestamptz,
 execution_id text, lease_token uuid, lease_until timestamptz, error_code text, old_pid integer, new_pid integer
);
CREATE UNIQUE INDEX service_restart_active ON status.service_restarts(service_id) WHERE state IN ('waiting','authorized','running');
GRANT SELECT ON status.service_restarts TO api_security,dashboard_admin;
CREATE FUNCTION status.request_restart(p_id uuid,p_actor uuid,p_service text,p_reason text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r status.service_restarts; q uuid; BEGIN
 IF session_user<>'api_security' OR NOT EXISTS(SELECT 1 FROM security.users u JOIN security.user_roles ur ON ur.user_id=u.id JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE u.id=p_actor AND u.status='active' AND rp.permission_code='deployment:service:restart') THEN RAISE EXCEPTION 'restart denied' USING ERRCODE='42501'; END IF;
 IF p_service NOT IN ('api','inventory','importer','enricher','matcher','findings','notification','dispatcher','ansible') OR length(btrim(p_reason)) NOT BETWEEN 3 AND 256 THEN RAISE EXCEPTION 'invalid restart' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(7349001);
 SELECT * INTO r FROM status.service_restarts WHERE id=p_id;
 IF r.id IS NOT NULL THEN
  IF r.actor_id<>p_actor OR r.service_id<>p_service OR r.reason<>p_reason THEN RAISE EXCEPTION 'request conflict' USING ERRCODE='23505'; END IF;
  RETURN to_jsonb(r);
 END IF;
 IF EXISTS(SELECT 1 FROM status.service_restarts WHERE service_id=p_service AND state IN ('waiting','authorized','running')) THEN RAISE EXCEPTION 'restart already pending' USING ERRCODE='23505'; END IF;
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,actor_id,correlation_id,deduplication_key)
 VALUES('command',session_user,'service.restart',jsonb_build_object('restart_id',p_id,'service_id',p_service),p_actor,p_id,'service-restart:'||p_id::text) RETURNING id INTO q;
 INSERT INTO status.service_restarts(id,queue_id,service_id,actor_id,reason) VALUES(p_id,q,p_service,p_actor,p_reason) RETURNING * INTO r;
 RETURN to_jsonb(r);
END $$;
REVOKE ALL ON FUNCTION status.request_restart(uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION status.request_restart(uuid,uuid,text,text) TO api_security;
ALTER FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) RENAME TO n8n_decide_v48;
REVOKE ALL ON FUNCTION automation.n8n_decide_v48(uuid,uuid,text,text,text) FROM workflow_control;
CREATE FUNCTION automation.n8n_decide(p_id uuid,p_token uuid,p_kind text,p_execution text,p_workflow text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q automation.n8n_queue; r status.service_restarts; BEGIN
 PERFORM pg_advisory_xact_lock(7348001);
 SELECT * INTO q FROM automation.n8n_queue WHERE id=p_id FOR UPDATE;
 IF q.kind IS DISTINCT FROM 'command' OR q.message_type IS DISTINCT FROM 'service.restart' THEN RETURN automation.n8n_decide_v48(p_id,p_token,p_kind,p_execution,p_workflow); END IF;
 IF session_user<>'workflow_control' OR p_workflow<>'cve-control-queue' THEN RAISE EXCEPTION 'n8n required' USING ERRCODE='42501'; END IF;
 IF q.state='completed' AND q.execution_id=p_execution AND q.workflow_id=p_workflow THEN RETURN jsonb_build_object('processed',true,'id',p_id); END IF;
 IF q.state<>'processing' OR q.kind<>p_kind OR p_kind<>'command' OR q.lease_token IS DISTINCT FROM p_token OR q.execution_id IS DISTINCT FROM p_execution OR q.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'stale queue receipt' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT r FROM status.service_restarts WHERE queue_id=p_id FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM security.users u JOIN security.user_roles ur ON ur.user_id=u.id JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE u.id=r.actor_id AND u.status='active' AND rp.permission_code='deployment:service:restart') THEN
  UPDATE status.service_restarts SET state='cancelled',finished_at=clock_timestamp(),error_code='REQUESTER_UNAVAILABLE' WHERE id=r.id;
  UPDATE automation.n8n_queue SET state='cancelled',finished_at=clock_timestamp(),error_code='requester_unavailable',lease_token=NULL,lease_until=NULL WHERE id=p_id;
 ELSE
  UPDATE status.service_restarts SET state='authorized',authorized_at=clock_timestamp(),execution_id=p_execution WHERE id=r.id AND state='waiting';
  UPDATE automation.n8n_queue SET state='completed',finished_at=clock_timestamp(),result=jsonb_build_object('restart_id',r.id,'authorized',true),lease_token=NULL,lease_until=NULL WHERE id=p_id;
 END IF;
 RETURN jsonb_build_object('processed',true,'id',p_id);
END $$;
REVOKE ALL ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) TO workflow_control;
CREATE FUNCTION status.claim_restart() RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r status.service_restarts; BEGIN
 IF session_user<>'dashboard_admin' THEN RAISE EXCEPTION 'host controller required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(7349001);
 SELECT s.* INTO r FROM status.service_restarts s JOIN automation.n8n_queue q ON q.id=s.queue_id WHERE q.state='completed' AND q.finished_at<clock_timestamp()-interval '2 seconds' AND (s.state='authorized' OR (s.state='running' AND s.lease_until<clock_timestamp())) ORDER BY s.requested_at LIMIT 1 FOR UPDATE OF s SKIP LOCKED;
 IF r.id IS NULL THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM security.users u JOIN security.user_roles ur ON ur.user_id=u.id JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE u.id=r.actor_id AND u.status='active' AND rp.permission_code='deployment:service:restart') THEN
  UPDATE status.service_restarts SET state='cancelled',finished_at=clock_timestamp(),error_code='REQUESTER_UNAVAILABLE' WHERE id=r.id;
  RETURN NULL;
 END IF;
 UPDATE status.service_restarts SET state='running',started_at=coalesce(started_at,clock_timestamp()),lease_token=gen_random_uuid(),lease_until=clock_timestamp()+interval '120 seconds' WHERE id=r.id RETURNING * INTO r;
 RETURN jsonb_build_object('id',r.id,'service_id',r.service_id,'lease_token',r.lease_token);
END $$;
CREATE FUNCTION status.finish_restart(p_id uuid,p_token uuid,p_ok boolean,p_error text,p_old integer,p_new integer) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r status.service_restarts; BEGIN
 IF session_user<>'dashboard_admin' THEN RAISE EXCEPTION 'host controller required' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM status.service_restarts WHERE id=p_id FOR UPDATE;
 IF r.state<>'running' OR r.lease_token IS DISTINCT FROM p_token OR r.lease_until<clock_timestamp() THEN RAISE EXCEPTION 'stale restart receipt' USING ERRCODE='42501'; END IF;
 IF NOT p_ok AND p_error NOT IN ('RESTART_FAILED','SERVICE_NOT_READY') THEN RAISE EXCEPTION 'invalid failure'; END IF;
 UPDATE status.service_restarts SET state=CASE WHEN p_ok THEN 'succeeded' ELSE 'failed' END,finished_at=clock_timestamp(),lease_token=NULL,lease_until=NULL,error_code=p_error,old_pid=p_old,new_pid=p_new WHERE id=p_id;
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,actor_id,correlation_id,deduplication_key)
 VALUES('result',session_user,'service.restart',jsonb_build_object('restart_id',p_id,'service_id',r.service_id,'status',CASE WHEN p_ok THEN 'succeeded' ELSE 'failed' END,'error_code',p_error),r.actor_id,r.id,'service-restart-result:'||p_id::text) ON CONFLICT DO NOTHING;
END $$;
REVOKE ALL ON FUNCTION status.claim_restart(),status.finish_restart(uuid,uuid,boolean,text,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION status.claim_restart(),status.finish_restart(uuid,uuid,boolean,text,integer,integer) TO dashboard_admin;
CREATE FUNCTION status.control_sample() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
WITH active AS MATERIALIZED (SELECT state,available_at,lease_until,correlation_id FROM automation.n8n_queue WHERE state IN ('pending','processing') ORDER BY sequence LIMIT 10001)
SELECT jsonb_build_object('enabled',automation.workflow_enabled(),'heartbeat_at',(SELECT seen_at FROM automation.n8n_consumer),
 'pending',(SELECT count(*) FROM active WHERE state='pending'),'processing',(SELECT count(*) FROM active WHERE state='processing'),
 'paused',(SELECT count(*) FROM active q WHERE EXISTS(SELECT 1 FROM automation.workflow_runs r WHERE r.correlation_id=q.correlation_id AND r.paused AND NOT r.cancelled)),
 'failed',(SELECT count(*) FROM automation.n8n_queue WHERE state='failed'),
 'oldest_seconds',coalesce((SELECT greatest(0,extract(epoch FROM clock_timestamp()-min(available_at))) FROM active q WHERE available_at<=clock_timestamp() AND NOT EXISTS(SELECT 1 FROM automation.workflow_runs r WHERE r.correlation_id=q.correlation_id AND r.paused AND NOT r.cancelled)),0),
 'expired_leases',(SELECT count(*) FROM active WHERE state='processing' AND lease_until<clock_timestamp()),
 'capped',(SELECT count(*)>=10001 FROM active));
$$;
REVOKE ALL ON FUNCTION status.control_sample() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION status.control_sample() TO status_probe,api_security;
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO d;
 EXECUTE replace(d,'00048_n8n_message_queue','00049_control_status_restart');
END $$;
"""
