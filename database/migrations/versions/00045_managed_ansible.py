"""n8n-managed server connections, encrypted credentials, durable runs and fenced ingestion."""

from alembic import op

revision = "00045_managed_ansible"
down_revision = "00044_finding_software"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Restore the verified backup and preserve server identity bindings")


DDL = r"""
GRANT USAGE ON SCHEMA inventory,security,automation TO ansible_worker;
GRANT SELECT ON automation.jobs,automation.workflow_requests,inventory.servers TO ansible_worker;
DO $$ DECLARE routine record; BEGIN
 FOR routine IN SELECT p.oid::regprocedure AS name FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='automation' AND p.proname IN ('claim_job','heartbeat_job','finish_job','check_job_fence','emit_event','recover_jobs') LOOP
 EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO ansible_worker',routine.name);
 END LOOP;
END $$;
CREATE FUNCTION inventory.grant_server_owner(p_server uuid,p_actor uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF session_user<>'dashboard_admin' OR NOT EXISTS(SELECT 1 FROM inventory.servers WHERE id=p_server AND created_by=p_actor)
 THEN RAISE EXCEPTION 'owner grant denied' USING ERRCODE='42501'; END IF;
 INSERT INTO security.user_server_access(user_id,server_id,can_read,can_upload,findings_read,granted_by)
 VALUES(p_actor,p_server,true,true,true,p_actor) ON CONFLICT DO NOTHING;
END $$;
REVOKE ALL ON FUNCTION inventory.grant_server_owner(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION inventory.grant_server_owner(uuid,uuid) TO dashboard_admin;
CREATE TABLE inventory.ansible_profiles (
 server_id uuid PRIMARY KEY REFERENCES inventory.servers(id),owner_id uuid NOT NULL REFERENCES security.users(id),
 host text NOT NULL CHECK(length(host) BETWEEN 1 AND 253),port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),
 username text NOT NULL CHECK(username ~ '^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$'),auth_method text NOT NULL CHECK(auth_method IN ('key','password')),
 key_id text NOT NULL,ciphertext bytea NOT NULL,version bigint NOT NULL DEFAULT 1,
 enabled boolean NOT NULL DEFAULT false,interval_seconds integer NOT NULL DEFAULT 21600 CHECK(interval_seconds BETWEEN 300 AND 604800),
 next_due timestamptz NOT NULL DEFAULT clock_timestamp(),host_key text,host_key_confirmed boolean NOT NULL DEFAULT false,
 use_sudo boolean NOT NULL DEFAULT false,mount_paths jsonb NOT NULL DEFAULT '[]',
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE inventory.ansible_runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),server_id uuid NOT NULL REFERENCES inventory.servers(id),
 profile_version bigint NOT NULL,action text NOT NULL CHECK(action IN ('collect','test','probe')),
 trigger_type text NOT NULL CHECK(trigger_type IN ('manual','schedule')),requested_by uuid REFERENCES security.users(id),
 job_id uuid REFERENCES automation.jobs(id),state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','running','succeeded','failed')),
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),started_at timestamptz,finished_at timestamptz,
 error_code text,host_key text,submission_id uuid REFERENCES inventory.submissions(id),execution_id text,workflow_id text,
 UNIQUE(job_id)
);
CREATE INDEX ansible_server_runs ON inventory.ansible_runs(server_id,requested_at DESC);
GRANT SELECT,INSERT,UPDATE,DELETE ON inventory.ansible_profiles TO api_security,dashboard_admin;
GRANT SELECT ON inventory.ansible_profiles,inventory.ansible_runs,inventory.servers TO ansible_worker;
GRANT SELECT ON inventory.ansible_runs TO api_security,dashboard_admin,reporter;
INSERT INTO automation.job_types(code,handler_role,producer_roles,runtime_seconds,max_attempts)
 VALUES('inventory.ansible','ansible_worker',ARRAY['api_security','dashboard_admin','workflow_control']::name[],2400,3);
UPDATE automation.job_types SET producer_roles=array_append(producer_roles,'ansible_worker'::name)
 WHERE code='inventory.process_submission';
INSERT INTO automation.event_types(code,producer_role,source)
 VALUES('workflow.ansible_worker.inventory','ansible_worker','workflow-ansible-worker'),
 ('workflow.dashboard_admin.inventory','dashboard_admin','workflow-dashboard-admin');
GRANT EXECUTE ON FUNCTION automation.enqueue_job(text,integer,jsonb,text,uuid,integer,timestamptz,timestamptz,integer,text,boolean,uuid),
 automation.workflow_enabled(),automation.workflow_stage(text),
 automation.emit_event(uuid,text,integer,text,text,text,bigint,jsonb,text,uuid) TO ansible_worker;
CREATE FUNCTION inventory.ansible_owner_active(p_owner uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM security.users u JOIN security.user_roles ur ON ur.user_id=u.id
 JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE u.id=p_owner AND u.status='active'
 AND rp.permission_code='server:inventory:manage') $$;
REVOKE ALL ON FUNCTION inventory.ansible_owner_active(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION inventory.ansible_owner_active(uuid) TO api_security,dashboard_admin,ansible_worker,workflow_control;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('automation.enqueue_job(text,integer,jsonb,text,uuid,integer,timestamptz,timestamptz,integer,text,boolean,uuid)'::regprocedure) INTO definition;
 EXECUTE replace(definition,'IF automation.workflow_enabled() AND flow_stage IS NOT NULL THEN',
 'IF (automation.workflow_enabled() OR p_type=''inventory.ansible'') AND flow_stage IS NOT NULL THEN');
END $$;
CREATE FUNCTION inventory.schedule_ansible(p_server uuid,p_action text,p_actor uuid DEFAULT NULL)
 RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE profile inventory.ansible_profiles; rid uuid; jid uuid;
BEGIN
 IF session_user NOT IN ('api_security','dashboard_admin','workflow_control') OR p_action NOT IN ('collect','test','probe')
 THEN RAISE EXCEPTION 'collection context denied' USING ERRCODE='42501'; END IF;
 SELECT p.* INTO profile FROM inventory.ansible_profiles p JOIN inventory.servers s ON s.id=p.server_id
 WHERE p.server_id=p_server AND s.status='active' AND inventory.ansible_owner_active(p.owner_id) FOR UPDATE OF p;
 IF profile.server_id IS NULL THEN RAISE EXCEPTION 'collection profile unavailable' USING ERRCODE='P0002'; END IF;
 IF p_action<>'probe' AND NOT profile.host_key_confirmed THEN RAISE EXCEPTION 'host key confirmation required' USING ERRCODE='23514'; END IF;
 SELECT r.id INTO rid FROM inventory.ansible_runs r JOIN automation.jobs j ON j.id=r.job_id
 WHERE r.server_id=p_server AND j.status IN ('pending','queued','running','retry_pending') ORDER BY r.requested_at DESC LIMIT 1;
 IF rid IS NOT NULL THEN RETURN rid; END IF;
 INSERT INTO inventory.ansible_runs(server_id,profile_version,action,trigger_type,requested_by)
 VALUES(p_server,profile.version,p_action,CASE WHEN session_user='workflow_control' THEN 'schedule' ELSE 'manual' END,p_actor) RETURNING id INTO rid;
 SELECT id INTO jid FROM automation.enqueue_job('inventory.ansible',1,jsonb_build_object('run_id',rid),
 'ansible:'||rid::text,gen_random_uuid(),0,NULL,NULL,3,'ansible',false);
 UPDATE inventory.ansible_runs SET job_id=jid WHERE id=rid;
 RETURN rid;
END $$;
REVOKE ALL ON FUNCTION inventory.schedule_ansible(uuid,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION inventory.schedule_ansible(uuid,text,uuid) TO api_security,dashboard_admin,workflow_control;
CREATE FUNCTION inventory.managed_ansible_tick() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target record; n integer:=0; BEGIN
 IF session_user<>'workflow_control' THEN RAISE EXCEPTION 'n8n required' USING ERRCODE='42501'; END IF;
 FOR target IN SELECT p.server_id FROM inventory.ansible_profiles p JOIN inventory.servers s ON s.id=p.server_id
 WHERE p.enabled AND p.host_key_confirmed AND p.next_due<=clock_timestamp() AND s.status='active'
 AND inventory.ansible_owner_active(p.owner_id) ORDER BY p.next_due LIMIT 64 FOR UPDATE OF p SKIP LOCKED LOOP
  PERFORM inventory.schedule_ansible(target.server_id,'collect',NULL);
  UPDATE inventory.ansible_profiles SET next_due=clock_timestamp()+make_interval(secs=>interval_seconds) WHERE server_id=target.server_id;
  n:=n+1;
 END LOOP;
 RETURN n;
END $$;
REVOKE ALL ON FUNCTION inventory.managed_ansible_tick() FROM PUBLIC;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('automation.workflow_tick(text,text,text)'::regprocedure) INTO definition;
 EXECUTE replace(definition,'inventory.collection_tick(p_execution,p_workflow)',
 'inventory.collection_tick(p_execution,p_workflow)+inventory.managed_ansible_tick()');
 SELECT pg_get_functiondef('inventory.schedule_submission(uuid)'::regprocedure) INTO definition;
 EXECUTE replace(definition,'''api_ingest'',''api_security'',''inventory_processor''','''api_ingest'',''api_security'',''inventory_processor'',''ansible_worker''');
END $$;
-- Managed submissions bind to a live, n8n-authorized run. A deleted run cannot be replayed.
ALTER TABLE inventory.submissions ADD COLUMN ansible_run_id uuid REFERENCES inventory.ansible_runs(id);
DO $$ DECLARE c record; definition text; BEGIN
 FOR c IN SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid='inventory.submissions'::regclass
 AND contype='c' AND (pg_get_constraintdef(oid) LIKE '%source%ansible_api%' OR pg_get_constraintdef(oid) LIKE '%source%dashboard_file%') LOOP
  EXECUTE format('ALTER TABLE inventory.submissions DROP CONSTRAINT %I',c.conname);
 END LOOP;
 SELECT pg_get_functiondef('inventory.accept_submission()'::regprocedure) INTO definition;
 definition:=replace(definition,' IF (session_user=',
 ' IF NEW.source=''managed_ansible'' AND (session_user<>''ansible_worker'' OR NOT EXISTS(
 SELECT 1 FROM inventory.ansible_runs r JOIN inventory.ansible_profiles p ON p.server_id=r.server_id
 JOIN automation.jobs j ON j.id=r.job_id JOIN automation.workflow_requests w ON w.job_id=j.id
 WHERE r.id=NEW.ansible_run_id AND r.server_id=NEW.server_id AND r.profile_version=p.version
 AND r.action=''collect'' AND p.host_key_confirmed AND NEW.actor_user_id=p.owner_id
 AND inventory.ansible_owner_active(p.owner_id) AND j.status=''running'' AND j.lease_until>clock_timestamp() AND w.released_at IS NOT NULL))
 THEN RAISE EXCEPTION ''stale collection'' USING ERRCODE=''42501''; END IF;
 IF (session_user=');
 EXECUTE definition;
 SELECT pg_get_functiondef('inventory.resolve_upload_host(jsonb,uuid,uuid,uuid)'::regprocedure) INTO definition;
 definition:=replace(definition,'''api_security'',''api_ingest''','''api_security'',''api_ingest'',''ansible_worker''');
 EXECUTE definition;
END $$;
ALTER TABLE inventory.submissions ADD CHECK(source IN ('ansible_api','dashboard_file','managed_ansible')),
 ADD CHECK((source='managed_ansible' AND ansible_run_id IS NOT NULL AND source_identity=ansible_run_id AND actor_user_id IS NOT NULL
 AND session_reference IS NULL AND technical_principal_id IS NULL AND token_id IS NULL AND certificate_id IS NULL)
 OR (source='ansible_api' AND ansible_run_id IS NULL AND technical_principal_id IS NOT NULL AND token_id IS NOT NULL AND certificate_id IS NOT NULL
 AND source_identity=technical_principal_id AND actor_user_id IS NULL AND session_reference IS NULL)
 OR (source='dashboard_file' AND ansible_run_id IS NULL AND actor_user_id IS NOT NULL AND session_reference IS NOT NULL
 AND source_identity=actor_user_id AND technical_principal_id IS NULL AND token_id IS NULL AND certificate_id IS NULL));
GRANT EXECUTE ON FUNCTION inventory.resolve_upload_host(jsonb,uuid,uuid,uuid) TO ansible_worker;
CREATE FUNCTION inventory.ansible_run_update(p_run uuid,p_state text,p_error text DEFAULT NULL,p_key text DEFAULT NULL,p_submission uuid DEFAULT NULL)
 RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF session_user<>'ansible_worker' OR p_state NOT IN ('running','failed','succeeded') THEN RAISE EXCEPTION 'executor required' USING ERRCODE='42501'; END IF;
 UPDATE inventory.ansible_runs r SET state=p_state,started_at=coalesce(r.started_at,clock_timestamp()),
 finished_at=CASE WHEN p_state IN ('failed','succeeded') THEN clock_timestamp() END,error_code=p_error,host_key=p_key,
 submission_id=p_submission,execution_id=w.execution_id,workflow_id=w.workflow_id
 FROM inventory.ansible_profiles p,automation.workflow_requests w,automation.jobs j
 WHERE r.id=p_run AND p.server_id=r.server_id AND p.version=r.profile_version AND j.id=r.job_id
 AND j.status='running' AND w.job_id=j.id AND w.released_at IS NOT NULL;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION inventory.ansible_run_update(uuid,text,text,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION inventory.ansible_run_update(uuid,text,text,text,uuid) TO ansible_worker;
GRANT SELECT,INSERT ON inventory.submissions,inventory.submission_identities TO ansible_worker;
GRANT EXECUTE ON FUNCTION inventory.has_administration_fields(jsonb) TO ansible_worker;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00044_finding_software','00045_managed_ansible');
END $$;
"""
