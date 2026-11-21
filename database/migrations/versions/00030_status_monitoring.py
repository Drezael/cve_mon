"""Least-privilege observations and status metadata; existing domain rows are preserved."""

from alembic import op

revision = "00030_status_monitoring"
down_revision = "00029_dashboard_administration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use reviewed data-preserving backup/restore")


DDL = r"""
CREATE SCHEMA status AUTHORIZATION postgres_owner;
REVOKE ALL ON SCHEMA status FROM PUBLIC;
GRANT USAGE ON SCHEMA status TO status_probe,api_security;
GRANT EXECUTE ON FUNCTION system.safe_metadata(jsonb),system.has_reserved_key(jsonb,text[]) TO status_probe;
CREATE TABLE status.entities (
 id text PRIMARY KEY CHECK(id ~ '^[a-z][a-z0-9-]{0,63}$'),
 kind text NOT NULL CHECK(kind IN ('service','pipeline')), name text NOT NULL,
 dependencies text[] NOT NULL,critical boolean NOT NULL DEFAULT true, version integer NOT NULL DEFAULT 1
);
CREATE TABLE status.check_definitions (
 service_id text NOT NULL REFERENCES status.entities(id),check_id text NOT NULL,
 version integer NOT NULL CHECK(version>0),dimension text NOT NULL,
 interval_seconds integer NOT NULL CHECK(interval_seconds>=30),stale_seconds integer NOT NULL CHECK(stale_seconds>=90),
 configuration jsonb NOT NULL CHECK(system.safe_metadata(configuration)),
 PRIMARY KEY(service_id,check_id,version)
);
CREATE TABLE status.monitoring_runs (
 id uuid PRIMARY KEY,started_at timestamptz NOT NULL,finished_at timestamptz NOT NULL,
 correlation_id uuid NOT NULL,observation_count integer NOT NULL CHECK(observation_count>=0),
 CHECK(finished_at>=started_at)
);
CREATE TABLE status.check_observations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),run_id uuid NOT NULL REFERENCES status.monitoring_runs(id),
 service_id text NOT NULL,check_id text NOT NULL,definition_version integer NOT NULL DEFAULT 1,
 checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),result text NOT NULL,
 duration_ms double precision NOT NULL CHECK(duration_ms>=0 AND duration_ms<=60000),reason_code text NOT NULL,
 metrics jsonb NOT NULL CHECK(jsonb_typeof(metrics)='object' AND system.safe_metadata(metrics)),
 FOREIGN KEY(service_id,check_id,definition_version) REFERENCES status.check_definitions(service_id,check_id,version),
 UNIQUE(run_id,service_id,check_id),
 CHECK(result IN ('healthy','degraded','unavailable','unknown','starting')),
 CHECK(reason_code ~ '^[A-Z][A-Z0-9_]{0,63}$')
);
CREATE INDEX status_observations_history ON status.check_observations(service_id,checked_at DESC,id);
CREATE INDEX status_observations_retention ON status.check_observations(checked_at,id);
CREATE TABLE status.current_states (
 entity_id text PRIMARY KEY REFERENCES status.entities(id),raw_state text NOT NULL,state text NOT NULL,
 reason_code text NOT NULL,observed_at timestamptz NOT NULL,last_success_at timestamptz,
 run_id uuid NOT NULL REFERENCES status.monitoring_runs(id),failures integer NOT NULL,successes integer NOT NULL,
 changes integer NOT NULL DEFAULT 0,version bigint NOT NULL DEFAULT 1,
 CHECK(raw_state IN ('healthy','degraded','unavailable','unknown','starting')),
 CHECK(state IN ('healthy','degraded','unavailable','unknown','starting'))
);
CREATE TABLE status.state_history (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),entity_id text NOT NULL REFERENCES status.entities(id),
 previous_state text,state text NOT NULL,raw_state text NOT NULL,reason_code text NOT NULL,
 observed_at timestamptz NOT NULL,decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 run_id uuid NOT NULL REFERENCES status.monitoring_runs(id),version bigint NOT NULL,UNIQUE(entity_id,version)
);
CREATE INDEX status_state_history_page ON status.state_history(entity_id,observed_at DESC,id);
CREATE TABLE status.incidents (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),entity_id text NOT NULL REFERENCES status.entities(id),
 state text NOT NULL CHECK(state IN ('open','resolved')),reason_code text NOT NULL,
 opened_at timestamptz NOT NULL,resolved_at timestamptz,version bigint NOT NULL DEFAULT 1,
 CHECK((state='resolved')=(resolved_at IS NOT NULL))
);
CREATE UNIQUE INDEX status_incident_dedup ON status.incidents(entity_id) WHERE state='open';
CREATE INDEX status_incidents_page ON status.incidents(opened_at DESC,id);
CREATE TABLE status.incident_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),incident_id uuid NOT NULL REFERENCES status.incidents(id),
 version bigint NOT NULL,kind text NOT NULL CHECK(kind IN ('opened','changed','recovered')),
 reason_code text NOT NULL,run_id uuid NOT NULL REFERENCES status.monitoring_runs(id),
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(incident_id,version)
);
CREATE INDEX status_incident_events_page ON status.incident_events(incident_id,occurred_at,id);
CREATE TABLE status.maintenance_windows (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),service_ids text[] NOT NULL,
 starts_at timestamptz NOT NULL,ends_at timestamptz NOT NULL,description text NOT NULL CHECK(length(description) BETWEEN 3 AND 512),
 actor_user_id uuid NOT NULL REFERENCES security.users(id),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 cancelled boolean NOT NULL DEFAULT false,version bigint NOT NULL DEFAULT 1,
 CHECK(ends_at>starts_at AND ends_at-starts_at<=interval '90 days'),CHECK(cardinality(service_ids) BETWEEN 1 AND 20)
);
CREATE INDEX status_maintenance_time ON status.maintenance_windows(starts_at,ends_at) WHERE NOT cancelled;
CREATE TABLE status.audit (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),actor_user_id uuid NOT NULL REFERENCES security.users(id),
 object_id uuid NOT NULL REFERENCES status.maintenance_windows(id),action text NOT NULL,reason text NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),version bigint NOT NULL,old_value jsonb,new_value jsonb NOT NULL CHECK(system.safe_metadata(new_value))
);
CREATE TABLE status.alert_receipts (
 incident_id uuid NOT NULL REFERENCES status.incidents(id),incident_version bigint NOT NULL,
 event_id uuid NOT NULL UNIQUE REFERENCES automation.event_outbox(id),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 state text NOT NULL DEFAULT 'outbox_recorded' CHECK(state='outbox_recorded'),
 PRIMARY KEY(incident_id,incident_version)
);
CREATE TABLE status.source_expectations (
 source_id text PRIMARY KEY REFERENCES cve.sources(id), max_age_seconds integer NOT NULL CHECK(max_age_seconds BETWEEN 300 AND 2592000),
 enabled boolean NOT NULL DEFAULT true,version bigint NOT NULL DEFAULT 1
);
GRANT SELECT ON ALL TABLES IN SCHEMA status TO status_probe,api_security;
GRANT INSERT ON status.entities,status.check_definitions,status.monitoring_runs,status.check_observations,status.current_states,status.state_history,status.incidents,status.incident_events,status.alert_receipts TO status_probe;
GRANT UPDATE ON status.current_states,status.incidents TO status_probe;
GRANT INSERT,UPDATE ON status.maintenance_windows TO api_security;
GRANT INSERT ON status.audit TO api_security;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON status.check_definitions FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON status.monitoring_runs FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON status.state_history FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON status.incident_events FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON status.audit FOR EACH ROW EXECUTE FUNCTION system.append_only();
REVOKE UPDATE,DELETE ON status.check_observations FROM status_probe,api_security;
CREATE FUNCTION status.prune(p_days integer) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n integer;
BEGIN
 IF session_user<>'status_probe' OR p_days NOT BETWEEN 1 AND 90 THEN RAISE EXCEPTION 'denied' USING ERRCODE='42501'; END IF;
 DELETE FROM status.check_observations WHERE id IN (SELECT o.id FROM status.check_observations o WHERE checked_at<clock_timestamp()-make_interval(days=>p_days) AND NOT EXISTS(SELECT 1 FROM status.current_states c WHERE c.run_id=o.run_id) ORDER BY checked_at LIMIT 1000);
 GET DIAGNOSTICS n=ROW_COUNT;RETURN n;
END $$;
REVOKE ALL ON FUNCTION status.prune(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION status.prune(integer) TO status_probe;
INSERT INTO automation.job_types(code,handler_role,producer_roles,max_attempts,payload_version,runtime_seconds)
 VALUES('status.collect','status_probe',ARRAY['status_probe']::name[],1,1,45);
GRANT USAGE ON SCHEMA automation TO status_probe;
DO $$ DECLARE f regprocedure; BEGIN
 FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='automation' AND p.proname IN ('check_job_fence','enqueue_job','claim_job','heartbeat_job','finish_job','recover_jobs','job_effect','complete_job')
 LOOP EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO status_probe',f); END LOOP;
END $$;
CREATE FUNCTION status.sample() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
WITH active AS MATERIALIZED (
 SELECT job_type,status,scheduled_at,heartbeat_at,lease_until FROM automation.jobs
 WHERE runtime_version=1 AND job_type<>'status.collect' AND status IN ('queued','retry_pending','running')
 ORDER BY scheduled_at,id LIMIT 10001
), recent AS MATERIALIZED (
 SELECT job_type,status,finished_at FROM automation.jobs WHERE runtime_version=1 AND finished_at>clock_timestamp()-interval '24 hours'
 ORDER BY finished_at DESC LIMIT 10001
), grouped AS (
 SELECT job_type,count(*) FILTER(WHERE status='queued') AS queued,count(*) FILTER(WHERE status='retry_pending') AS retry_pending,
 count(*) FILTER(WHERE status='running') AS running,
 count(*) FILTER(WHERE status='running' AND lease_until<clock_timestamp()) AS expired_leases,
 greatest(0,extract(epoch FROM clock_timestamp()-min(scheduled_at) FILTER(WHERE status IN ('queued','retry_pending') AND scheduled_at<=clock_timestamp()))) AS oldest_seconds,
 greatest(0,extract(epoch FROM clock_timestamp()-max(heartbeat_at) FILTER(WHERE status='running'))) AS heartbeat_age_seconds FROM active GROUP BY job_type
), done AS (
 SELECT job_type,count(*) FILTER(WHERE status='failed' OR status='timed_out') AS failed,
 count(*) FILTER(WHERE status='succeeded') AS completed,
 greatest(0,extract(epoch FROM clock_timestamp()-max(finished_at) FILTER(WHERE status='succeeded'))) AS last_success_age_seconds
 FROM recent GROUP BY job_type
), deliveries AS MATERIALIZED (
 SELECT status,next_attempt_at,lease_until FROM automation.event_deliveries WHERE runtime_version=1 AND status IN ('pending','retry_pending','running') ORDER BY next_attempt_at,event_id,destination LIMIT 10001
), pending_inventory AS MATERIALIZED (
 SELECT received_at FROM inventory.submissions s WHERE NOT EXISTS(SELECT 1 FROM inventory.processing_status p WHERE p.submission_id=s.id AND p.status IN ('completed','rejected_after_acceptance')) ORDER BY received_at LIMIT 10001
), notification_rows AS MATERIALIZED (
 SELECT status,scheduled_at FROM automation.notification_intents WHERE status IN ('ready','deferred','leased','submitting','retryable_failure','submission_uncertain') ORDER BY scheduled_at LIMIT 10001
)
SELECT jsonb_build_object(
 'jobs',coalesce((SELECT jsonb_agg(to_jsonb(q)) FROM (SELECT coalesce(g.job_type,d.job_type) AS job_type,g.queued,g.retry_pending,g.running,g.expired_leases,g.oldest_seconds,g.heartbeat_age_seconds,d.failed,d.completed,d.last_success_age_seconds FROM grouped g FULL JOIN done d USING(job_type)) q),'[]'),
 'capped',(SELECT count(*)>=10001 FROM active),
 'outbox',jsonb_build_object('pending',(SELECT count(*) FROM deliveries),'oldest_seconds',(SELECT greatest(0,extract(epoch FROM clock_timestamp()-min(next_attempt_at))) FROM deliveries),'expired_leases',(SELECT count(*) FROM deliveries WHERE status='running' AND lease_until<clock_timestamp()),'capped',(SELECT (count(*)>=10001)::integer FROM deliveries)),
 'intake',jsonb_build_object('pending',(SELECT count(*) FROM pending_inventory),'oldest_seconds',(SELECT greatest(0,extract(epoch FROM clock_timestamp()-min(received_at))) FROM pending_inventory),'capped',(SELECT (count(*)>=10001)::integer FROM pending_inventory)),
 'notification',jsonb_build_object('pending',(SELECT count(*) FROM notification_rows),'uncertain',(SELECT count(*) FROM notification_rows WHERE status='submission_uncertain'),'oldest_seconds',(SELECT greatest(0,extract(epoch FROM clock_timestamp()-min(scheduled_at))) FROM notification_rows WHERE scheduled_at<=clock_timestamp()),'capped',(SELECT (count(*)>=10001)::integer FROM notification_rows)),
 'sources',coalesce((SELECT jsonb_agg(jsonb_build_object('id',e.source_id,'max_age_seconds',e.max_age_seconds,'last_success',(SELECT finished_at FROM cve.import_runs r WHERE r.source_id=e.source_id AND r.status='completed' ORDER BY finished_at DESC LIMIT 1))) FROM status.source_expectations e WHERE enabled),'[]'),
 'matching',jsonb_build_object('uncovered',(SELECT count(*) FROM (SELECT i.server_id FROM inventory.server_current_snapshots i WHERE NOT EXISTS(SELECT 1 FROM matching.current_evaluations e WHERE e.server_id=i.server_id AND e.snapshot_id=i.snapshot_id AND e.is_current) LIMIT 10001) q)),
 'enrichment',jsonb_build_object('last_success_age_seconds',(SELECT greatest(0,extract(epoch FROM clock_timestamp()-r.completed_at)) FROM cve.epss_current_dataset d JOIN cve.epss_import_runs r ON r.id=d.dataset_id),'stale',(SELECT current_date-r.score_date>2 FROM cve.epss_current_dataset d JOIN cve.epss_import_runs r ON r.id=d.dataset_id)),
 'workflow',jsonb_build_object('expired_leases',(SELECT count(*) FROM (SELECT id FROM automation.notification_workflow_runs WHERE state IN ('requested','executing') AND expires_at<clock_timestamp() LIMIT 10001) q),'last_success_age_seconds',(SELECT greatest(0,extract(epoch FROM clock_timestamp()-completed_at)) FROM automation.notification_workflow_runs WHERE state='completed' ORDER BY completed_at DESC LIMIT 1)),
 'schema_ready', (SELECT version_num='00030_status_monitoring' FROM public.alembic_version)
);
$$;
REVOKE ALL ON FUNCTION status.sample() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION status.sample() TO status_probe;
CREATE INDEX IF NOT EXISTS jobs_status_recent ON automation.jobs(finished_at DESC,job_type) WHERE runtime_version=1 AND finished_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS status_import_success ON cve.import_runs(source_id,finished_at DESC) WHERE status='completed';
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES
 ('deployment:diagnostics:read','Platform diagnosis read','human',true,NULL,false,false),
 ('deployment:maintenance:manage','Platform maintenance metadata','human',true,NULL,true,false);
INSERT INTO security.role_permissions(role_id,permission_code) SELECT id,p FROM security.roles CROSS JOIN unnest(ARRAY['deployment:diagnostics:read','deployment:maintenance:manage']) p WHERE code='admin';
"""

DDL += r"""
INSERT INTO automation.event_types(code,producer_role,source,schema_version,requires_order) VALUES
 ('monitoring.status_unavailable','status_probe','cve-status',1,true),
 ('monitoring.status_recovered','status_probe','cve-status',1,true);
GRANT EXECUTE ON FUNCTION automation.emit_event(uuid,text,integer,text,text,text,bigint,jsonb,text,uuid) TO status_probe;
UPDATE automation.job_types SET producer_roles=array_append(producer_roles,'status_probe'::name) WHERE code='notifications.consume_event';
CREATE FUNCTION status.schedule_alert() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.source='cve-status' AND NEW.aggregate_type='status_incident' AND NEW.event_type IN ('monitoring.status_unavailable','monitoring.status_recovered') THEN
 PERFORM automation.enqueue_job('notifications.consume_event',1,jsonb_build_object('event_id',NEW.id),'notification-event:'||NEW.id::text,NEW.correlation_id,0,NULL,NULL,3,'notification-events',false);
 END IF; RETURN NEW;
END $$;
CREATE TRIGGER schedule_status_alert AFTER INSERT ON automation.event_outbox FOR EACH ROW EXECUTE FUNCTION status.schedule_alert();
ALTER TABLE automation.notification_intents ADD status_incident_id uuid REFERENCES status.incidents(id);
DO $$ DECLARE name text; BEGIN
 FOR name IN SELECT conname FROM pg_constraint WHERE conrelid='automation.notification_intents'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%kind%' LOOP
 EXECUTE format('ALTER TABLE automation.notification_intents DROP CONSTRAINT %I',name);
 END LOOP;
END $$;
ALTER TABLE automation.notification_intents ADD CHECK(
 (kind='digest' AND event_id IS NULL AND finding_id IS NULL AND status_incident_id IS NULL)
 OR (kind IN ('status_unavailable','status_recovered') AND event_id IS NOT NULL AND finding_id IS NULL AND status_incident_id IS NOT NULL)
 OR (kind NOT IN ('digest','status_unavailable','status_recovered') AND event_id IS NOT NULL AND finding_id IS NOT NULL AND status_incident_id IS NULL));
GRANT USAGE ON SCHEMA status TO notification;
GRANT SELECT ON status.incidents,status.entities TO notification;
CREATE FUNCTION status.recipient(p_user uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM security.users u JOIN security.user_roles ur ON ur.user_id=u.id JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE u.id=p_user AND u.status='active' AND rp.permission_code='deployment:diagnostics:read');
$$;
REVOKE ALL ON FUNCTION status.recipient(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION status.recipient(uuid) TO notification;
"""

DDL += r"""
CREATE FUNCTION status.alert_identity() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.status_incident_id IS DISTINCT FROM OLD.status_incident_id THEN RAISE EXCEPTION 'immutable status reference' USING ERRCODE='23514'; END IF; RETURN NEW;
END $$;
CREATE TRIGGER status_alert_identity BEFORE UPDATE ON automation.notification_intents FOR EACH ROW EXECUTE FUNCTION status.alert_identity();
"""

DDL += r"""
CREATE INDEX status_workflows_due ON automation.notification_workflow_runs(expires_at) WHERE state IN ('requested','executing');
CREATE INDEX status_workflows_success ON automation.notification_workflow_runs(completed_at DESC) WHERE state='completed';
"""

DDL += r"""
CREATE INDEX status_incident_filter ON status.incidents(entity_id,state,opened_at DESC,id);
CREATE OR REPLACE VIEW dashboard.administration_audit AS
 SELECT id,occurred_at,actor_user_id,action,object_type,object_id,outcome FROM security.audit_log
 UNION ALL SELECT id,occurred_at,actor_user_id,'finding.'||kind,'finding',finding_id::text,'success' FROM findings.audit_events
 UNION ALL SELECT id,occurred_at,actor_user_id,'notification.'||action,'notification',object_id::text,'success' FROM automation.notification_audit
 UNION ALL SELECT id,occurred_at,actor_user_id,'status.'||action,'maintenance',object_id::text,'success' FROM status.audit;
"""
