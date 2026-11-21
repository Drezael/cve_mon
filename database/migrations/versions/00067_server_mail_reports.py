"""Scan-complete server notifications and personal weekly reports controlled by n8n."""

from alembic import op

revision = "00067_server_mail_reports"
down_revision = "00066_new_finding_notifications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)
    definition = driver.execute(
        "SELECT pg_get_functiondef('automation.n8n_decide(uuid,uuid,text,text,text)'::regprocedure)"
    ).fetchone()[0]
    # Keep the existing recovery/restart/SMTP command chain intact.
    driver.execute(
        "ALTER FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) RENAME TO n8n_decide_v66",
        prepare=False,
    )
    driver.execute(QUEUE, prepare=False)
    driver.execute(
        "REVOKE ALL ON FUNCTION automation.n8n_decide_v66(uuid,uuid,text,text,text) FROM workflow_control",
        prepare=False,
    )
    assert definition


def downgrade() -> None:
    raise RuntimeError("Preserve report schedules and delivery receipts")


DDL = r"""
CREATE TABLE automation.mail_report_schedules(
 user_id uuid PRIMARY KEY REFERENCES security.users(id) ON DELETE CASCADE,
 version bigint NOT NULL DEFAULT 1,configuration jsonb NOT NULL,
 next_run_at timestamptz NOT NULL,updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE automation.mail_reports(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),user_id uuid NOT NULL REFERENCES security.users(id) ON DELETE CASCADE,
 origin text NOT NULL CHECK(origin IN ('scan','weekly','manual')),
 scan_server_id uuid REFERENCES inventory.servers(id) ON DELETE CASCADE,
 correlation_id uuid NOT NULL,state text NOT NULL DEFAULT 'requested'
 CHECK(state IN ('requested','scanning','ready','failed','cancelled')),
 notification_id uuid UNIQUE REFERENCES automation.notification_intents(id) ON DELETE CASCADE,
 error_code text,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz,
 UNIQUE(user_id,correlation_id,scan_server_id)
);
CREATE TABLE automation.mail_report_servers(
 report_id uuid NOT NULL REFERENCES automation.mail_reports(id) ON DELETE CASCADE,
 server_id uuid NOT NULL REFERENCES inventory.servers(id) ON DELETE CASCADE,
 snapshot_id uuid REFERENCES inventory.snapshots(id) ON DELETE SET NULL,
 PRIMARY KEY(report_id,server_id)
);
CREATE INDEX mail_reports_pending ON automation.mail_reports(created_at,id) WHERE state IN ('requested','scanning');
CREATE INDEX mail_report_server_lookup ON automation.mail_report_servers(server_id,report_id);
CREATE INDEX report_job_snapshot ON automation.jobs((payload->>'snapshot_id')) WHERE job_type LIKE 'matching.%';
GRANT SELECT ON automation.mail_report_schedules,automation.mail_reports,automation.mail_report_servers TO api_security,notification,reporter;
GRANT INSERT,UPDATE ON automation.mail_reports,automation.mail_report_servers TO notification;
GRANT SELECT ON inventory.server_current_snapshots,inventory.snapshots,automation.jobs TO notification;

CREATE INDEX report_jobs_active_correlation ON automation.jobs(correlation_id)
WHERE status IN ('pending','queued','running','retry_pending');
CREATE FUNCTION automation.mail_report_barrier(p_report uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
WITH report AS MATERIALIZED (SELECT * FROM automation.mail_reports WHERE id=p_report),
servers AS MATERIALIZED (SELECT srv.server_id,c.snapshot_id FROM automation.mail_report_servers srv
 LEFT JOIN inventory.server_current_snapshots c ON c.server_id=srv.server_id WHERE srv.report_id=p_report),
contexts AS MATERIALIZED (
 SELECT correlation_id FROM report
 UNION SELECT j.correlation_id FROM servers s JOIN matching.current_results c ON c.server_id=s.server_id
 JOIN matching.result_revisions r ON r.id=c.result_id JOIN matching.runs run ON run.id=r.run_id
 JOIN automation.jobs j ON j.id=run.job_id
 UNION SELECT j.correlation_id FROM automation.jobs j WHERE j.job_type LIKE 'matching.%'
 AND j.status IN ('pending','queued','running','retry_pending')
 AND j.payload->>'snapshot_id' IN (SELECT snapshot_id::text FROM servers)
)
SELECT jsonb_build_object('busy',EXISTS(SELECT 1 FROM automation.jobs j
 WHERE j.correlation_id IN (SELECT correlation_id FROM contexts)
 AND j.status IN ('pending','queued','running','retry_pending')
 AND (j.job_type LIKE 'matching.%' OR j.job_type LIKE 'findings.%' OR j.job_type LIKE 'inventory.%'
 OR j.job_type LIKE 'cve.import.%' OR j.job_type LIKE 'cve.enrich.%' OR j.job_type='notifications.consume_event')
 AND NOT EXISTS(SELECT 1 FROM automation.jobs child WHERE child.replay_of=j.id)),
 'failed',EXISTS(SELECT 1 FROM automation.jobs j JOIN report r ON r.correlation_id=j.correlation_id
 WHERE j.status IN ('failed','timed_out','cancelled')
 AND (j.job_type LIKE 'matching.%' OR j.job_type LIKE 'findings.%' OR j.job_type LIKE 'inventory.%'
 OR j.job_type LIKE 'cve.import.%' OR j.job_type LIKE 'cve.enrich.%' OR j.job_type='notifications.consume_event')
 AND NOT EXISTS(SELECT 1 FROM automation.jobs child WHERE child.replay_of=j.id)))
$$;
REVOKE ALL ON FUNCTION automation.mail_report_barrier(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.mail_report_barrier(uuid) TO notification;

CREATE FUNCTION automation.report_server_access(p_user uuid,p_server uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM security.users u JOIN inventory.servers s ON s.id=p_server
 WHERE u.id=p_user AND u.status='active' AND s.status='active'
 AND EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.role_permissions rp ON rp.role_id=ur.role_id
 WHERE ur.user_id=u.id AND rp.permission_code='finding:read')
 AND (EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id
 WHERE ur.user_id=u.id AND r.code='admin') OR EXISTS(SELECT 1 FROM security.user_server_access a
 WHERE a.user_id=u.id AND a.server_id=s.id AND a.findings_read)))
$$;
REVOKE ALL ON FUNCTION automation.report_server_access(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.report_server_access(uuid,uuid) TO api_security,notification,workflow_control;

CREATE FUNCTION automation.report_next_run(p_config jsonb,p_after timestamptz) RETURNS timestamptz
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE zone text:=p_config->>'timezone'; candidate timestamp; BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_timezone_names WHERE name=zone)
 OR (p_config->>'weekday')::integer NOT BETWEEN 0 AND 6
 OR p_config->>'time' !~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'
 THEN RAISE EXCEPTION 'invalid weekly schedule' USING ERRCODE='22023'; END IF;
 candidate:=date_trunc('week',p_after AT TIME ZONE zone)+make_interval(days=>(p_config->>'weekday')::integer)+((p_config->>'time')::time-time '00:00');
 IF candidate AT TIME ZONE zone<=p_after THEN candidate:=candidate+interval '7 days'; END IF;
 RETURN candidate AT TIME ZONE zone;
END $$;
REVOKE ALL ON FUNCTION automation.report_next_run(jsonb,timestamptz) FROM PUBLIC;

CREATE FUNCTION automation.report_schedule_set(p_actor uuid,p_version bigint,p_config jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old automation.mail_report_schedules; BEGIN
 IF session_user<>'api_security' OR NOT EXISTS(SELECT 1 FROM security.users WHERE id=p_actor AND status='active')
 OR NOT system.safe_metadata(p_config) THEN RAISE EXCEPTION 'report settings denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_actor::text,67001));
 SELECT * INTO old FROM automation.mail_report_schedules WHERE user_id=p_actor FOR UPDATE;
 IF coalesce(old.version,0)<>p_version THEN RAISE EXCEPTION 'schedule version conflict' USING ERRCODE='40001'; END IF;
 INSERT INTO automation.mail_report_schedules(user_id,version,configuration,next_run_at)
 VALUES(p_actor,p_version+1,p_config,automation.report_next_run(p_config,clock_timestamp()))
 ON CONFLICT(user_id) DO UPDATE SET version=excluded.version,configuration=excluded.configuration,
 next_run_at=excluded.next_run_at,updated_at=clock_timestamp();
 RETURN (SELECT to_jsonb(r)-'user_id' FROM automation.mail_report_schedules r WHERE user_id=p_actor);
END $$;
REVOKE ALL ON FUNCTION automation.report_schedule_set(uuid,bigint,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.report_schedule_set(uuid,bigint,jsonb) TO api_security;

CREATE FUNCTION automation.request_mail_report(p_actor uuid,p_key uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r automation.mail_reports; BEGIN
 IF session_user<>'api_security' OR NOT EXISTS(SELECT 1 FROM security.users WHERE id=p_actor AND status='active')
 THEN RAISE EXCEPTION 'report request denied' USING ERRCODE='42501'; END IF;
 INSERT INTO automation.mail_reports(id,user_id,origin,correlation_id) VALUES(p_key,p_actor,'manual',p_key)
 ON CONFLICT(id) DO NOTHING;
 SELECT * INTO STRICT r FROM automation.mail_reports WHERE id=p_key;
 IF r.user_id<>p_actor OR r.origin<>'manual' THEN RAISE EXCEPTION 'report conflict' USING ERRCODE='23505'; END IF;
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,actor_id,correlation_id,deduplication_key)
 VALUES('command',session_user,'reports.scan',jsonb_build_object('report_id',p_key),p_actor,p_key,'mail-report:'||p_key::text)
 ON CONFLICT DO NOTHING;
 RETURN jsonb_build_object('id',r.id,'state',r.state);
END $$;
REVOKE ALL ON FUNCTION automation.request_mail_report(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.request_mail_report(uuid,uuid) TO api_security;

CREATE FUNCTION automation.report_weekly_tick() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE schedule automation.mail_report_schedules; rid uuid; n integer:=0;
 default_config jsonb:='{"enabled":true,"weekday":0,"time":"09:00","timezone":"Europe/Berlin"}'; BEGIN
 IF session_user<>'notification' THEN RAISE EXCEPTION 'report scheduler denied' USING ERRCODE='42501'; END IF;
 INSERT INTO automation.mail_report_schedules(user_id,configuration,next_run_at)
 SELECT u.id,default_config,automation.report_next_run(default_config,clock_timestamp()) FROM security.users u
 WHERE u.status='active' AND EXISTS(SELECT 1 FROM inventory.servers srv WHERE automation.report_server_access(u.id,srv.id))
 AND EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.role_permissions rp
 ON rp.role_id=ur.role_id WHERE ur.user_id=u.id AND rp.permission_code='notification:preferences:update')
 ON CONFLICT DO NOTHING;
 FOR schedule IN SELECT cfg.* FROM automation.mail_report_schedules cfg JOIN security.users u ON u.id=cfg.user_id
 WHERE u.status='active' AND cfg.configuration->'enabled'='true'::jsonb AND cfg.next_run_at<=clock_timestamp()
 ORDER BY cfg.next_run_at LIMIT 100 FOR UPDATE OF cfg SKIP LOCKED LOOP
 rid:=gen_random_uuid();
 INSERT INTO automation.mail_reports(id,user_id,origin,correlation_id) VALUES(rid,schedule.user_id,'weekly',rid);
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,correlation_id,deduplication_key)
 VALUES('command',session_user,'reports.scan',jsonb_build_object('report_id',rid),rid,'mail-report:'||rid::text);
 UPDATE automation.mail_report_schedules SET next_run_at=automation.report_next_run(configuration,clock_timestamp()),updated_at=clock_timestamp()
 WHERE user_id=schedule.user_id;
 n:=n+1;
 END LOOP;
 RETURN n;
END $$;
REVOKE ALL ON FUNCTION automation.report_weekly_tick() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.report_weekly_tick() TO notification;

CREATE FUNCTION automation.start_mail_report(p_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r automation.mail_reports; s record; n integer:=0; BEGIN
 IF session_user<>'workflow_control' THEN RAISE EXCEPTION 'n8n report context required' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT r FROM automation.mail_reports WHERE id=p_id FOR UPDATE;
 IF r.state<>'requested' THEN RETURN jsonb_build_object('id',r.id,'state',r.state); END IF;
 IF NOT EXISTS(SELECT 1 FROM security.users WHERE id=r.user_id AND status='active') THEN
 UPDATE automation.mail_reports SET state='cancelled',error_code='recipient_unavailable' WHERE id=p_id;
 RETURN jsonb_build_object('id',r.id,'state','cancelled'); END IF;
 FOR s IN SELECT srv.id,c.snapshot_id FROM inventory.servers srv LEFT JOIN inventory.server_current_snapshots c ON c.server_id=srv.id
 WHERE automation.report_server_access(r.user_id,srv.id) ORDER BY srv.id LOOP
 INSERT INTO automation.mail_report_servers VALUES(r.id,s.id,s.snapshot_id);
 IF s.snapshot_id IS NOT NULL THEN
 PERFORM automation.enqueue_job('matching.evaluate_snapshot',1,jsonb_build_object('snapshot_id',s.snapshot_id),
 r.id::text||':'||s.id::text,r.correlation_id,0,NULL,NULL,3,'weekly-report',false);
 END IF;
 n:=n+1;
 END LOOP;
 UPDATE automation.mail_reports SET state='scanning' WHERE id=p_id;
 RETURN jsonb_build_object('id',r.id,'state','scanning','servers',n);
END $$;
REVOKE ALL ON FUNCTION automation.start_mail_report(uuid) FROM PUBLIC;
UPDATE automation.job_types SET producer_roles=array_append(producer_roles,'workflow_control'::name)
WHERE code='matching.evaluate_snapshot' AND NOT ('workflow_control'=ANY(producer_roles));

-- Replace the per-CVE default with report-only delivery. Administrative rule history stays immutable.
INSERT INTO automation.notification_rules(rule_key,version,config,reason)
SELECT rule_key,version+1,config||'{"enabled":false}'::jsonb,'Replaced by complete server scan reports'
FROM (SELECT DISTINCT ON(rule_key) * FROM automation.notification_rules ORDER BY rule_key,version DESC) r
WHERE config->'enabled'='true'::jsonb AND NOT (config->'event_types' ? 'status_unavailable' OR config->'event_types' ? 'status_recovered');
INSERT INTO automation.notification_rules(rule_key,version,config,reason) VALUES
('00000000-0000-0000-0000-000000000067',1,
 '{"enabled":true,"event_types":["created"],"minimum_priority":"unrated","recipients":"server_owner","rate_per_hour":100}',
 'Complete server scan and weekly report delivery');
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00066_new_finding_notifications','00067_server_mail_reports');
END $$;
"""

QUEUE = r"""
CREATE FUNCTION automation.n8n_decide(p_id uuid,p_token uuid,p_kind text,p_execution text,p_workflow text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q automation.n8n_queue; r automation.mail_reports; answer jsonb; BEGIN
 PERFORM pg_advisory_xact_lock(7348001);
 SELECT * INTO q FROM automation.n8n_queue WHERE id=p_id FOR UPDATE;
 IF q.kind IS DISTINCT FROM 'command' OR q.message_type IS DISTINCT FROM 'reports.scan' THEN
 RETURN automation.n8n_decide_v66(p_id,p_token,p_kind,p_execution,p_workflow); END IF;
 IF session_user<>'workflow_control' OR p_workflow<>'cve-control-queue' THEN RAISE EXCEPTION 'n8n required' USING ERRCODE='42501'; END IF;
 IF q.state='completed' AND q.execution_id=p_execution AND q.workflow_id=p_workflow THEN RETURN jsonb_build_object('processed',true,'id',p_id); END IF;
 IF q.state<>'processing' OR p_kind<>'command' OR q.lease_token IS DISTINCT FROM p_token OR q.execution_id IS DISTINCT FROM p_execution
 OR q.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'stale report receipt' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT r FROM automation.mail_reports WHERE id=(q.payload->>'report_id')::uuid;
 IF q.actor_id IS NOT NULL AND q.actor_id<>r.user_id THEN RAISE EXCEPTION 'report actor mismatch' USING ERRCODE='42501'; END IF;
 answer:=automation.start_mail_report(r.id);
 UPDATE automation.n8n_queue SET state='completed',finished_at=clock_timestamp(),lease_token=NULL,lease_until=NULL,result=answer WHERE id=p_id;
 RETURN jsonb_build_object('processed',true,'id',p_id);
END $$;
REVOKE ALL ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.n8n_decide(uuid,uuid,text,text,text) TO workflow_control;
"""
