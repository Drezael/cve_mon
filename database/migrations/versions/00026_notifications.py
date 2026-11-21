"""Persistent notification decisions, delivery fences, immutable history and read-only sources."""

from alembic import op

revision = "00026_notifications"
down_revision = "00025_finding_commands"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use verified data-preserving backup/restore")


DDL = r"""
CREATE VIEW automation.notification_finding_changes AS
 SELECT finding_id,finding_version,kind,old_value->>'current_priority' AS old_priority,
 new_value->>'current_priority' AS new_priority,
 old_value->'priority_basis'->>'kev_status' AS old_kev,
 new_value->'priority_basis'->>'kev_status' AS new_kev
 FROM findings.audit_events WHERE kind='priority_changed';
GRANT SELECT ON automation.notification_finding_changes TO notification;
CREATE VIEW automation.notification_due_exceptions AS
 SELECT id,finding_id,valid_until FROM findings.exception_state WHERE is_active;
GRANT SELECT ON automation.notification_due_exceptions TO notification;
CREATE TABLE automation.notification_exception_warnings (
 exception_id uuid PRIMARY KEY REFERENCES findings.exceptions(id),event_id uuid NOT NULL REFERENCES automation.event_outbox(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON automation.notification_exception_warnings FOR EACH ROW EXECUTE FUNCTION system.append_only();
GRANT SELECT,INSERT ON automation.notification_exception_warnings TO notification;
INSERT INTO automation.event_types(code,producer_role,source) VALUES('notification.exception_approaching','notification','cve-notification');
CREATE TABLE automation.notification_rules (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), rule_key uuid NOT NULL, version bigint NOT NULL CHECK(version>0),
 config jsonb NOT NULL CHECK(jsonb_typeof(config)='object' AND system.safe_metadata(config)),
 actor_user_id uuid REFERENCES security.users(id), reason text NOT NULL CHECK(length(reason) BETWEEN 3 AND 1024),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(rule_key,version)
);
CREATE TABLE automation.notification_templates (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL CHECK(name IN ('finding','digest')), language text NOT NULL CHECK(language='de'),
 version bigint NOT NULL CHECK(version>0), content jsonb NOT NULL CHECK(jsonb_typeof(content)='object' AND system.safe_metadata(content)),
 actor_user_id uuid REFERENCES security.users(id), reason text NOT NULL CHECK(length(reason) BETWEEN 3 AND 1024),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(name,language,version)
);
CREATE TABLE automation.notification_preferences (
 user_id uuid PRIMARY KEY REFERENCES security.users(id), version bigint NOT NULL CHECK(version>0),
 config jsonb NOT NULL CHECK(jsonb_typeof(config)='object' AND system.safe_metadata(config)), updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE automation.notification_event_receipts (
 event_id uuid PRIMARY KEY REFERENCES automation.event_outbox(id), outcome text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE automation.notification_intents (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), event_id uuid REFERENCES automation.event_outbox(id),
 finding_id uuid REFERENCES findings.findings(id), recipient_user_id uuid NOT NULL REFERENCES security.users(id),
 rule_id uuid NOT NULL REFERENCES automation.notification_rules(id), template_id uuid NOT NULL REFERENCES automation.notification_templates(id),
 channel text NOT NULL DEFAULT 'email' CHECK(channel='email'), kind text NOT NULL,
 status text NOT NULL CHECK(status IN ('planned','suppressed','deferred','ready','leased','submitting','relay_accepted','retryable_failure','permanent_failure','submission_uncertain','upstream_accepted','bounced','delivery_confirmed','cancelled')),
 reason text NOT NULL, version bigint NOT NULL DEFAULT 1 CHECK(version>0), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 scheduled_at timestamptz NOT NULL DEFAULT clock_timestamp(), message_id text GENERATED ALWAYS AS ('<'||id::text||'@cve-monitoring.invalid>') STORED,
 digest_id uuid REFERENCES automation.notification_intents(id), window_start timestamptz, window_end timestamptz,
 lease_owner uuid, lease_until timestamptz, fencing_token bigint NOT NULL DEFAULT 0 CHECK(fencing_token>=0),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5), correlation_id uuid NOT NULL,
 CHECK((kind='digest')=(event_id IS NULL AND finding_id IS NULL)),
 CHECK(kind='digest' OR (event_id IS NOT NULL AND finding_id IS NOT NULL)),
 CHECK((window_start IS NULL)=(window_end IS NULL)), CHECK(window_end>window_start),
 CHECK((lease_owner IS NULL)=(lease_until IS NULL)),
 UNIQUE(event_id,recipient_user_id,channel,rule_id,kind), UNIQUE(recipient_user_id,rule_id,kind,window_start,window_end)
);
CREATE INDEX notification_due ON automation.notification_intents(scheduled_at,id) WHERE status IN ('ready','deferred','retryable_failure','leased','submitting');
CREATE INDEX notification_personal ON automation.notification_intents(recipient_user_id,created_at DESC,id);
CREATE TABLE automation.notification_delivery_attempts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), notification_id uuid NOT NULL REFERENCES automation.notification_intents(id),
 attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 5), fencing_token bigint NOT NULL CHECK(fencing_token>0), worker_id uuid NOT NULL,
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(), message_id text NOT NULL,
 UNIQUE(notification_id,attempt), UNIQUE(notification_id,fencing_token)
);
CREATE TABLE automation.notification_delivery_results (
 attempt_id uuid PRIMARY KEY REFERENCES automation.notification_delivery_attempts(id), status text NOT NULL CHECK(status IN ('relay_accepted','retryable_failure','permanent_failure','submission_uncertain')),
 reason text NOT NULL, smtp_code integer CHECK(smtp_code BETWEEN 200 AND 599), queue_id text CHECK(queue_id ~ '^[A-Za-z0-9]{5,64}$'),
 relay_instance text NOT NULL CHECK(length(relay_instance) BETWEEN 1 AND 128), created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE automation.notification_history (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), notification_id uuid NOT NULL REFERENCES automation.notification_intents(id),
 version bigint NOT NULL, old_status text, new_status text NOT NULL, reason text NOT NULL, correlation_id uuid NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(notification_id,version)
);
CREATE TABLE automation.notification_audit (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), actor_user_id uuid REFERENCES security.users(id), actor_session_id uuid REFERENCES security.sessions(id),
 action text NOT NULL, object_id uuid NOT NULL, reason text NOT NULL, old_value jsonb, new_value jsonb NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(), correlation_id uuid NOT NULL
);
CREATE TABLE automation.notification_rate_limits (
 recipient_user_id uuid NOT NULL REFERENCES security.users(id), rule_id uuid NOT NULL REFERENCES automation.notification_rules(id),
 window_start timestamptz NOT NULL, used integer NOT NULL CHECK(used BETWEEN 0 AND 100), PRIMARY KEY(recipient_user_id,rule_id,window_start)
);
CREATE TABLE automation.notification_workflow_runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), notification_id uuid REFERENCES automation.notification_intents(id),
 workflow text NOT NULL CHECK(workflow IN ('dispatch','digest','escalation','exception','reconciliation','health')),
 workflow_version integer NOT NULL CHECK(workflow_version=1), request_id uuid NOT NULL UNIQUE,
 state text NOT NULL CHECK(state IN ('requested','executing','completed','failed')), callback_seen boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL, completed_at timestamptz,
 CHECK((workflow='dispatch')=(notification_id IS NOT NULL))
);
CREATE INDEX notification_workflow_pending ON automation.notification_workflow_runs(created_at,id) WHERE state IN ('requested','executing');
CREATE TABLE automation.notification_transport_evidence (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), notification_id uuid NOT NULL REFERENCES automation.notification_intents(id),
 evidence_id text NOT NULL UNIQUE CHECK(length(evidence_id) BETWEEN 1 AND 256), relay_instance text NOT NULL,
 message_id text NOT NULL, queue_id text, status text NOT NULL CHECK(status IN ('relay_accepted','upstream_accepted','bounced','delivery_confirmed')),
 source text NOT NULL CHECK(source IN ('postfix','verified_dsn')), actor_user_id uuid REFERENCES security.users(id),
 reason text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['notification_rules','notification_templates','notification_event_receipts','notification_delivery_attempts','notification_delivery_results','notification_history','notification_audit','notification_transport_evidence'] LOOP
 EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON automation.%I FOR EACH ROW EXECUTE FUNCTION system.append_only()',t);
 END LOOP;
END $$;
CREATE FUNCTION automation.notification_recipient(p_user uuid,p_finding uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM security.users u JOIN findings.findings f ON f.id=p_finding
 JOIN inventory.servers s ON s.id=f.server_id
 WHERE u.id=p_user AND u.status='active' AND f.model_version=2 AND s.status='active'
 AND EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE ur.user_id=u.id AND rp.permission_code='finding:read')
 AND (EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id WHERE ur.user_id=u.id AND r.code='admin')
 OR EXISTS(SELECT 1 FROM security.user_server_access a WHERE a.user_id=u.id AND a.server_id=s.id AND a.findings_read)))
$$;
CREATE FUNCTION automation.notification_status_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
 IF (NEW.id,NEW.event_id,NEW.finding_id,NEW.recipient_user_id,NEW.rule_id,NEW.template_id,NEW.kind,NEW.created_at,NEW.correlation_id)
 IS DISTINCT FROM (OLD.id,OLD.event_id,OLD.finding_id,OLD.recipient_user_id,OLD.rule_id,OLD.template_id,OLD.kind,OLD.created_at,OLD.correlation_id)
 OR NEW.version<>OLD.version+1 THEN RAISE EXCEPTION 'immutable notification identity/version' USING ERRCODE='23514'; END IF;
 IF NEW.status<>OLD.status AND NOT (
 (OLD.status IN ('planned','ready','deferred','retryable_failure','leased') AND NEW.status IN ('ready','deferred','leased','submitting','suppressed','cancelled','permanent_failure')) OR
 (OLD.status='submitting' AND NEW.status IN ('relay_accepted','retryable_failure','permanent_failure','submission_uncertain')) OR
 (OLD.status='submission_uncertain' AND NEW.status IN ('relay_accepted','upstream_accepted','bounced','delivery_confirmed')) OR
 (OLD.status='relay_accepted' AND NEW.status IN ('upstream_accepted','bounced','delivery_confirmed')) OR
 (OLD.status='upstream_accepted' AND NEW.status IN ('bounced','delivery_confirmed')))
 THEN RAISE EXCEPTION 'illegal notification transition' USING ERRCODE='23514'; END IF;
 END IF; RETURN NEW;
END $$;
CREATE TRIGGER notification_state BEFORE UPDATE ON automation.notification_intents FOR EACH ROW EXECUTE FUNCTION automation.notification_status_guard();
CREATE FUNCTION automation.notification_history_required() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v bigint; BEGIN
 SELECT version INTO v FROM automation.notification_intents WHERE id=NEW.id;
 IF NOT EXISTS(SELECT 1 FROM automation.notification_history WHERE notification_id=NEW.id AND version=v) THEN
 RAISE EXCEPTION 'notification history required' USING ERRCODE='23514'; END IF; RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER notification_history_required AFTER INSERT OR UPDATE ON automation.notification_intents DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION automation.notification_history_required();
CREATE FUNCTION automation.notification_record(p_id uuid,p_old text,p_reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n automation.notification_intents;
BEGIN
 IF session_user NOT IN ('notification','api_security') THEN RAISE EXCEPTION 'notification context required' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT n FROM automation.notification_intents WHERE id=p_id;
 INSERT INTO automation.notification_history(notification_id,version,old_status,new_status,reason,correlation_id)
 VALUES(n.id,n.version,p_old,n.status,p_reason,n.correlation_id);
END $$;
GRANT USAGE ON SCHEMA findings,inventory,security TO notification;
GRANT SELECT ON findings.findings,findings.current_findings,inventory.servers,security.users,security.user_roles,security.roles,
 security.role_permissions,security.permissions,security.user_server_access TO notification;
GRANT SELECT ON automation.notification_rules,automation.notification_templates,automation.notification_preferences TO notification,api_security;
GRANT SELECT,INSERT,UPDATE ON automation.notification_intents,automation.notification_workflow_runs,automation.notification_rate_limits TO notification;
GRANT SELECT,INSERT ON automation.notification_event_receipts,automation.notification_delivery_attempts,automation.notification_delivery_results,automation.notification_history TO notification;
GRANT SELECT ON automation.notification_intents,automation.notification_workflow_runs,automation.notification_delivery_attempts,
 automation.notification_delivery_results,automation.notification_history,automation.notification_transport_evidence,automation.notification_audit TO api_security;
GRANT EXECUTE ON FUNCTION automation.notification_recipient(uuid,uuid),automation.notification_record(uuid,text,text) TO notification,api_security;
INSERT INTO automation.job_types(code,handler_role,producer_roles,runtime_seconds,max_attempts)
SELECT 'notifications.'||v,'notification',ARRAY['notification','findings_writer','api_security']::name[],3600,3
FROM unnest(ARRAY['consume_event','maintenance','orchestrate']) v;
CREATE FUNCTION automation.schedule_notification() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.source IN ('cve-findings','cve-api','cve-notification') AND NEW.aggregate_type='finding' AND NEW.event_type IN
 ('finding.created','finding.confirmed_affected','finding.potentially_affected','finding.reopened','finding.priority_changed','finding.resolved',
 'notification.exception_approaching','finding.closed','finding.assigned','finding.deadline_approaching','finding.overdue','finding.exception_approved','finding.exception_expired','finding.exception_revoked') THEN
 PERFORM automation.enqueue_job('notifications.consume_event',1,jsonb_build_object('event_id',NEW.id),'notification-event:'||NEW.id::text,NEW.correlation_id,0,NULL,NULL,3,'notification-events',false);
 END IF; RETURN NEW;
END $$;
CREATE TRIGGER schedule_notification AFTER INSERT ON automation.event_outbox FOR EACH ROW EXECUTE FUNCTION automation.schedule_notification();
-- Conservative initial rule is disabled until explicitly approved; no mail grants are created.
INSERT INTO automation.notification_rules(id,rule_key,version,config,reason) VALUES
('00000000-0000-0000-0000-000000000019','00000000-0000-0000-0000-000000000019',1,'{"enabled":false,"minimum_priority":"high","recipients":"assignee"}','Initial closed notification policy');
INSERT INTO automation.notification_templates(name,language,version,content,reason)
SELECT n,'de',1,jsonb_build_object('name',n,'language','de','subject','Sicherheitsmeldung: ${title}',
 'text','${title}'||chr(10)||'${items}'||chr(10)||'Dashboard: ${link}',
 'html','<h2>${title}</h2><p>${items}</p><p><a href="${link}">Geschütztes Dashboard</a></p>'),'Versioned German default'
FROM unnest(ARRAY['finding','digest']) n;
"""
