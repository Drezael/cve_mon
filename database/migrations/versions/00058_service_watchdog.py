"""Independent n8n watchdog with durable probes and bounded process-only recovery."""

from alembic import op

revision = "00058_service_watchdog"
down_revision = "00057_worker_recovery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve watchdog observations and restart receipts")


DDL = r"""
INSERT INTO security.technical_principals(name,status) VALUES('n8n-service-watchdog','active');
CREATE TABLE status.watchdog_settings (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), enabled boolean NOT NULL DEFAULT true,
 failure_threshold integer NOT NULL DEFAULT 3 CHECK(failure_threshold BETWEEN 2 AND 20),
 cooldown_seconds integer NOT NULL DEFAULT 300 CHECK(cooldown_seconds BETWEEN 60 AND 86400),
 hourly_limit integer NOT NULL DEFAULT 3 CHECK(hourly_limit BETWEEN 1 AND 12)
);
INSERT INTO status.watchdog_settings(singleton) VALUES(true);
CREATE TABLE status.watchdog_probes (
 service_id text PRIMARY KEY CHECK(service_id IN ('api','inventory','importer','enricher','matcher','findings','notification','dispatcher','ansible','cve-nginx','cve-postgres','cve-mail-relay','cve-n8n','cve-mailhog')),
 responsive boolean NOT NULL, restartable boolean NOT NULL, checked_at timestamptz NOT NULL,
 consecutive_failures integer NOT NULL DEFAULT 0, first_failure_at timestamptz,
 last_restart_at timestamptz, diagnostic_code text NOT NULL CHECK(diagnostic_code IN ('OK','UNRESPONSIVE','CONTAINER_UNAVAILABLE','VENDOR_UNHEALTHY'))
);
CREATE TABLE status.watchdog_runs (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), checked_at timestamptz NOT NULL,
 execution_id text NOT NULL, restart_count integer NOT NULL
);
ALTER TABLE status.service_restarts ALTER COLUMN actor_id DROP NOT NULL;
ALTER TABLE status.service_restarts ADD COLUMN origin text NOT NULL DEFAULT 'user' CHECK(origin IN ('user','watchdog'));
ALTER TABLE status.service_restarts ADD CONSTRAINT restart_actor_origin CHECK((origin='user' AND actor_id IS NOT NULL) OR (origin='watchdog' AND actor_id IS NULL));
GRANT USAGE ON SCHEMA status TO workflow_control;
GRANT SELECT ON status.watchdog_settings,status.watchdog_probes,status.watchdog_runs TO api_security,dashboard_admin;
CREATE FUNCTION status.watchdog_observe(p_service text,p_responsive boolean,p_restartable boolean,p_diagnostic text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'dashboard_admin' THEN RAISE EXCEPTION 'host observer required' USING ERRCODE='42501'; END IF;
 IF p_responsive IS NULL OR p_restartable IS NULL OR p_restartable IS DISTINCT FROM (p_service IN ('api','inventory','importer','enricher','matcher','findings','notification','dispatcher','ansible')) OR (p_responsive AND p_diagnostic<>'OK') OR (NOT p_responsive AND p_diagnostic='OK') THEN RAISE EXCEPTION 'invalid probe' USING ERRCODE='22023'; END IF;
 INSERT INTO status.watchdog_probes(service_id,responsive,restartable,checked_at,consecutive_failures,first_failure_at,diagnostic_code)
 VALUES(p_service,p_responsive,p_restartable,clock_timestamp(),CASE WHEN p_responsive THEN 0 ELSE 1 END,CASE WHEN p_responsive THEN NULL ELSE clock_timestamp() END,p_diagnostic)
 ON CONFLICT(service_id) DO UPDATE SET responsive=EXCLUDED.responsive,restartable=EXCLUDED.restartable,checked_at=EXCLUDED.checked_at,diagnostic_code=EXCLUDED.diagnostic_code,
 consecutive_failures=CASE WHEN EXCLUDED.responsive THEN 0 WHEN status.watchdog_probes.checked_at<clock_timestamp()-interval '75 seconds' OR EXCLUDED.diagnostic_code IS DISTINCT FROM status.watchdog_probes.diagnostic_code THEN 1 WHEN status.watchdog_probes.checked_at>clock_timestamp()-interval '20 seconds' THEN status.watchdog_probes.consecutive_failures ELSE least(status.watchdog_probes.consecutive_failures+1,1000) END,
 first_failure_at=CASE WHEN EXCLUDED.responsive THEN NULL WHEN status.watchdog_probes.checked_at<clock_timestamp()-interval '75 seconds' OR EXCLUDED.diagnostic_code IS DISTINCT FROM status.watchdog_probes.diagnostic_code THEN clock_timestamp() ELSE coalesce(status.watchdog_probes.first_failure_at,clock_timestamp()) END;
END $$;
CREATE FUNCTION status.watchdog_eligible(p_service text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM status.watchdog_probes p CROSS JOIN status.watchdog_settings s WHERE p.service_id=p_service AND s.enabled AND p.restartable AND NOT p.responsive AND p.diagnostic_code='UNRESPONSIVE' AND p.checked_at>clock_timestamp()-interval '75 seconds' AND p.consecutive_failures>=s.failure_threshold AND p.first_failure_at<=clock_timestamp()-make_interval(secs=>20*(s.failure_threshold-1))
 AND NOT EXISTS(SELECT 1 FROM status.maintenance_windows m WHERE NOT m.cancelled AND clock_timestamp() BETWEEN m.starts_at AND m.ends_at AND (p_service=ANY(m.service_ids) OR 'all'=ANY(m.service_ids)))
 AND EXISTS(SELECT 1 FROM status.watchdog_probes d WHERE d.service_id='cve-postgres' AND d.responsive AND d.checked_at>clock_timestamp()-interval '75 seconds'))
$$;
CREATE FUNCTION status.watchdog_tick(p_execution text,p_workflow text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p status.watchdog_probes; s status.watchdog_settings; request_id uuid; queue_id uuid; n integer:=0;
BEGIN
 IF session_user<>'workflow_control' OR p_workflow IS DISTINCT FROM 'cve-control-watchdog' OR p_execution !~ '^[A-Za-z0-9_-]{1,128}$' OR p_execution IS NULL THEN RAISE EXCEPTION 'n8n watchdog required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(7349001);
 SELECT * INTO STRICT s FROM status.watchdog_settings;
 FOR p IN SELECT * FROM status.watchdog_probes WHERE restartable ORDER BY service_id FOR UPDATE LOOP
  IF NOT status.watchdog_eligible(p.service_id) OR p.last_restart_at>clock_timestamp()-make_interval(secs=>s.cooldown_seconds)
   OR EXISTS(SELECT 1 FROM status.service_restarts r WHERE r.service_id=p.service_id AND r.state IN ('waiting','authorized','running'))
   OR (SELECT count(*) FROM status.service_restarts r WHERE r.service_id=p.service_id AND r.requested_at>clock_timestamp()-interval '1 hour')>=s.hourly_limit THEN CONTINUE; END IF;
  request_id:=gen_random_uuid();
  INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,correlation_id,deduplication_key,state,execution_id,workflow_id,finished_at,result)
  VALUES('command','n8n-service-watchdog','service.restart',jsonb_build_object('restart_id',request_id,'service_id',p.service_id),request_id,'service-restart:'||request_id::text,'completed',p_execution,p_workflow,clock_timestamp(),jsonb_build_object('restart_id',request_id,'authorized',true)) RETURNING id INTO queue_id;
  INSERT INTO status.service_restarts(id,queue_id,service_id,reason,origin,state,authorized_at,execution_id)
  VALUES(request_id,queue_id,p.service_id,'Automatische Wiederherstellung: Dienst reagiert wiederholt nicht','watchdog','authorized',clock_timestamp(),p_execution);
  UPDATE status.watchdog_probes SET last_restart_at=clock_timestamp() WHERE service_id=p.service_id;
  INSERT INTO security.audit_log(technical_principal_id,action,object_type,object_id,outcome,metadata)
  SELECT id,'service.watchdog.restart.authorized','service_restart',request_id::text,'success',jsonb_build_object('service_id',p.service_id,'failures',p.consecutive_failures) FROM security.technical_principals WHERE name='n8n-service-watchdog';
  n:=n+1;
 END LOOP;
 INSERT INTO status.watchdog_runs VALUES(true,clock_timestamp(),p_execution,n) ON CONFLICT(singleton) DO UPDATE SET checked_at=EXCLUDED.checked_at,execution_id=EXCLUDED.execution_id,restart_count=EXCLUDED.restart_count;
 RETURN jsonb_build_object('checked',true,'restarts',n);
END $$;
REVOKE ALL ON FUNCTION status.watchdog_observe(text,boolean,boolean,text),status.watchdog_eligible(text),status.watchdog_tick(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION status.watchdog_observe(text,boolean,boolean,text) TO dashboard_admin;
GRANT EXECUTE ON FUNCTION status.watchdog_tick(text,text) TO workflow_control;
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.claim_restart()'::regprocedure) INTO d;
 d:=replace(d,'IF NOT EXISTS(SELECT 1 FROM security.users','IF r.origin=''watchdog'' AND NOT status.watchdog_eligible(r.service_id) THEN
 UPDATE status.service_restarts SET state=''cancelled'',finished_at=clock_timestamp(),error_code=''PROBE_RECOVERED'' WHERE id=r.id;
 RETURN NULL;
 END IF;
 IF r.origin=''user'' AND NOT EXISTS(SELECT 1 FROM security.users');
 EXECUTE d;
 SELECT pg_get_functiondef('status.request_restart(uuid,uuid,text,text)'::regprocedure) INTO d;
 EXECUTE replace(d,'r.actor_id<>p_actor','r.actor_id IS DISTINCT FROM p_actor');
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00057_worker_recovery','00058_service_watchdog');
END $$;
CREATE FUNCTION status.audit_watchdog_restart() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.origin='watchdog' AND NEW.state IN ('succeeded','failed','cancelled') AND OLD.state IS DISTINCT FROM NEW.state THEN
 INSERT INTO security.audit_log(technical_principal_id,action,object_type,object_id,outcome,metadata)
 SELECT id,'service.watchdog.restart.finished','service_restart',NEW.id::text,CASE WHEN NEW.state='succeeded' THEN 'success' ELSE 'failure' END,jsonb_build_object('service_id',NEW.service_id,'state',NEW.state,'error_code',NEW.error_code) FROM security.technical_principals WHERE name='n8n-service-watchdog';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION status.audit_watchdog_restart() FROM PUBLIC;
CREATE TRIGGER audit_watchdog_restart AFTER UPDATE ON status.service_restarts FOR EACH ROW EXECUTE FUNCTION status.audit_watchdog_restart();
"""
