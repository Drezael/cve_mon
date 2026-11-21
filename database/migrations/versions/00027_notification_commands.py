"""Verified browser commands and transport evidence; no free mail or domain mutations."""

from alembic import op

revision = "00027_notification_commands"
down_revision = "00026_notifications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use verified data-preserving backup/restore")


DDL = r"""
GRANT EXECUTE ON FUNCTION findings.assignee_eligible(uuid,uuid) TO notification;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable)
SELECT 'notification:'||v,'Notification '||v,'human',v NOT IN ('read','preferences:update'),NULL,v IN ('rule:manage','template:manage'),false
FROM unnest(ARRAY['read','preferences:update','rule:read','rule:manage','template:read','template:manage','delivery:read','workflow:read']) v;
INSERT INTO security.role_permissions(role_id,permission_code)
SELECT r.id,p.code FROM security.roles r CROSS JOIN security.permissions p WHERE p.code LIKE 'notification:%'
AND (r.code='admin' OR (p.code IN ('notification:read','notification:preferences:update') AND r.code IN ('viewer','security_analyst')));
CREATE FUNCTION automation.notification_command(p_session uuid,p_kind text,p_id uuid,p_version bigint,p_config jsonb,p_reason text,p_correlation uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor uuid; action text; identity uuid; old jsonb; result jsonb; current_version bigint; current_key uuid;
BEGIN
 IF session_user<>'api_security' OR p_correlation IS NULL OR length(trim(p_reason)) NOT BETWEEN 3 AND 1024
 OR jsonb_typeof(p_config)<>'object' OR NOT system.safe_metadata(p_config) THEN
 RAISE EXCEPTION 'invalid notification command' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(909001);
 action:=CASE p_kind WHEN 'preferences' THEN 'notification:preferences:update' WHEN 'rule' THEN 'notification:rule:manage'
 WHEN 'template' THEN 'notification:template:manage' ELSE NULL END;
 IF action IS NULL THEN RAISE EXCEPTION 'unsupported notification command' USING ERRCODE='22023'; END IF;
 actor:=findings.authorize(p_session,NULL,action);
 PERFORM pg_advisory_xact_lock(hashtextextended('notification-command:'||coalesce(p_id,actor)::text||':'||p_kind,19));
 IF p_kind='preferences' THEN
 IF p_id IS NOT NULL AND p_id<>actor THEN RAISE EXCEPTION 'own preferences only' USING ERRCODE='42501'; END IF;
 SELECT to_jsonb(p),p.version INTO old,current_version FROM automation.notification_preferences p WHERE user_id=actor;
 IF p_version<>coalesce(current_version,0) THEN RAISE EXCEPTION 'stale notification preferences' USING ERRCODE='40001'; END IF;
 IF p_config->>'mode' NOT IN ('immediate','digest') OR p_config->>'language'<>'de' OR (p_config->>'digest_hours')::int NOT IN (1,24,168)
 THEN RAISE EXCEPTION 'invalid preferences' USING ERRCODE='22023'; END IF;
 INSERT INTO automation.notification_preferences(user_id,version,config) VALUES(actor,p_version+1,p_config)
 ON CONFLICT(user_id) DO UPDATE SET version=excluded.version,config=excluded.config,updated_at=clock_timestamp();
 SELECT to_jsonb(p) INTO result FROM automation.notification_preferences p WHERE user_id=actor; identity:=actor;
 ELSIF p_kind='rule' THEN
 current_key:=coalesce(p_id,gen_random_uuid());
 SELECT to_jsonb(r),r.version INTO old,current_version FROM automation.notification_rules r WHERE rule_key=current_key ORDER BY version DESC LIMIT 1;
 IF p_version<>coalesce(current_version,0) THEN RAISE EXCEPTION 'stale notification rule' USING ERRCODE='40001'; END IF;
 IF p_config->>'recipients' NOT IN ('assignee','administrators','authorized') OR p_config->>'mode' NOT IN ('immediate','digest')
 OR (p_config->>'rate_per_hour')::int NOT BETWEEN 1 AND 100 OR (p_config->>'max_deferral_hours')::int NOT BETWEEN 1 AND 720
 OR jsonb_typeof(p_config->'event_types')<>'array' THEN RAISE EXCEPTION 'invalid notification rule' USING ERRCODE='22023'; END IF;
 INSERT INTO automation.notification_rules(rule_key,version,config,actor_user_id,reason) VALUES(current_key,p_version+1,p_config,actor,p_reason)
 RETURNING to_jsonb(notification_rules),id INTO result,identity;
 ELSE
 IF p_config->>'name' NOT IN ('finding','digest') OR p_config->>'language'<>'de' OR length(p_config->>'subject') NOT BETWEEN 1 AND 160
 OR (p_config->>'subject') ~ '[\r\n]' THEN RAISE EXCEPTION 'invalid template' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('notification-template:'||(p_config->>'name'),19));
 SELECT to_jsonb(t),t.version INTO old,current_version FROM automation.notification_templates t WHERE name=p_config->>'name' AND language='de' ORDER BY version DESC LIMIT 1;
 IF p_version<>coalesce(current_version,0) THEN RAISE EXCEPTION 'stale template' USING ERRCODE='40001'; END IF;
 INSERT INTO automation.notification_templates(name,language,version,content,actor_user_id,reason)
 VALUES(p_config->>'name','de',p_version+1,p_config,actor,p_reason) RETURNING to_jsonb(notification_templates),id INTO result,identity;
 END IF;
 INSERT INTO automation.notification_audit(actor_user_id,actor_session_id,action,object_id,reason,old_value,new_value,correlation_id)
 VALUES(actor,p_session,p_kind,identity,p_reason,old,result,p_correlation);
 RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION automation.notification_command(uuid,text,uuid,bigint,jsonb,text,uuid) TO api_security;
CREATE FUNCTION automation.notification_evidence(p_session uuid,p_id uuid,p_evidence text,p_relay text,p_message text,p_queue text,p_status text,p_source text,p_reason text,p_correlation uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor uuid; n automation.notification_intents; result automation.notification_delivery_results;
BEGIN
 IF session_user<>'api_security' OR length(trim(p_reason)) NOT BETWEEN 3 AND 1024 OR p_status NOT IN ('relay_accepted','upstream_accepted','bounced','delivery_confirmed')
 OR p_source NOT IN ('postfix','verified_dsn') OR (p_status='delivery_confirmed' AND p_source<>'verified_dsn') THEN
 RAISE EXCEPTION 'verified transport evidence required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(909001);
 actor:=findings.authorize(p_session,NULL,'notification:rule:manage');
 SELECT * INTO STRICT n FROM automation.notification_intents WHERE id=p_id FOR UPDATE;
 IF n.message_id<>p_message OR n.status NOT IN ('submitting','submission_uncertain','relay_accepted','upstream_accepted')
 OR NOT EXISTS(SELECT 1 FROM automation.notification_delivery_attempts a WHERE a.notification_id=n.id)
 THEN RAISE EXCEPTION 'uncorrelated transport evidence' USING ERRCODE='23514'; END IF;
 SELECT r.* INTO result FROM automation.notification_delivery_results r JOIN automation.notification_delivery_attempts a ON a.id=r.attempt_id
 WHERE a.notification_id=n.id ORDER BY a.attempt DESC LIMIT 1;
 IF result.relay_instance IS NOT NULL AND result.relay_instance<>p_relay OR result.queue_id IS NOT NULL AND result.queue_id IS DISTINCT FROM p_queue
 THEN RAISE EXCEPTION 'wrong relay instance or queue' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM automation.notification_transport_evidence WHERE evidence_id=p_evidence) THEN RETURN; END IF;
 INSERT INTO automation.notification_transport_evidence(notification_id,evidence_id,relay_instance,message_id,queue_id,status,source,actor_user_id,reason)
 VALUES(n.id,p_evidence,p_relay,p_message,p_queue,p_status,p_source,actor,p_reason);
 UPDATE automation.notification_intents SET status=p_status,reason='verified_transport_evidence',version=version+1,lease_owner=NULL,lease_until=NULL WHERE id=n.id;
 PERFORM automation.notification_record(n.id,n.status,p_reason);
 INSERT INTO automation.notification_audit(actor_user_id,actor_session_id,action,object_id,reason,new_value,correlation_id)
 VALUES(actor,p_session,'transport_evidence',n.id,p_reason,jsonb_build_object('status',p_status,'evidence_id',p_evidence),p_correlation);
END $$;
GRANT EXECUTE ON FUNCTION automation.notification_evidence(uuid,uuid,text,text,text,text,text,text,text,uuid) TO api_security;
CREATE TABLE automation.notification_transport_samples (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),relay_instance text NOT NULL,queue_depth integer NOT NULL CHECK(queue_depth>=0),
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON automation.notification_transport_samples FOR EACH ROW EXECUTE FUNCTION system.append_only();
GRANT INSERT,SELECT ON automation.notification_transport_samples TO notification;
CREATE FUNCTION automation.notification_observe(p_id uuid,p_evidence text,p_relay text,p_queue text,p_status text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n automation.notification_intents; last_result automation.notification_delivery_results;
BEGIN
 IF session_user<>'notification' OR p_status NOT IN ('relay_accepted','upstream_accepted','bounced')
 OR p_queue !~ '^[A-Za-z0-9]{5,64}$' THEN RAISE EXCEPTION 'trusted Postfix observation required' USING ERRCODE='42501'; END IF;
 SELECT * INTO n FROM automation.notification_intents WHERE id=p_id FOR UPDATE;
 IF n.id IS NULL OR n.status NOT IN ('submitting','submission_uncertain','relay_accepted','upstream_accepted') THEN RETURN false; END IF;
 IF n.status='upstream_accepted' AND p_status='relay_accepted' THEN RETURN false; END IF;
 SELECT r.* INTO last_result FROM automation.notification_delivery_attempts a LEFT JOIN automation.notification_delivery_results r ON r.attempt_id=a.id
 WHERE a.notification_id=n.id ORDER BY a.attempt DESC LIMIT 1;
 IF NOT FOUND OR (last_result.relay_instance IS NOT NULL AND last_result.relay_instance<>p_relay)
 OR (last_result.queue_id IS NOT NULL AND last_result.queue_id<>p_queue) THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM automation.notification_transport_evidence WHERE evidence_id=p_evidence) THEN RETURN false; END IF;
 INSERT INTO automation.notification_transport_evidence(notification_id,evidence_id,relay_instance,message_id,queue_id,status,source,reason)
 VALUES(n.id,p_evidence,p_relay,n.message_id,p_queue,p_status,'postfix','Own-instance Postfix log observation');
 IF n.status='submitting' AND p_status<>'relay_accepted' THEN
 UPDATE automation.notification_intents SET status='submission_uncertain',reason='postfix_reconciliation',version=version+1,lease_owner=NULL,lease_until=NULL WHERE id=n.id;
 PERFORM automation.notification_record(n.id,n.status,'postfix_reconciliation'); n.status:='submission_uncertain';
 END IF;
 IF n.status<>p_status THEN
 UPDATE automation.notification_intents SET status=p_status,reason='postfix_reconciliation',version=version+1,lease_owner=NULL,lease_until=NULL WHERE id=n.id;
 PERFORM automation.notification_record(n.id,n.status,'postfix_reconciliation');
 END IF; RETURN true;
END $$;
GRANT EXECUTE ON FUNCTION automation.notification_observe(uuid,text,text,text,text) TO notification;

CREATE FUNCTION automation.notification_metrics() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('states',(SELECT coalesce(jsonb_object_agg(status,n),'{}') FROM (SELECT status,count(*) n FROM automation.notification_intents GROUP BY status) s),
 'workflow_failures',(SELECT count(*) FROM automation.notification_workflow_runs WHERE state='failed'),
 'workflow_pending',(SELECT count(*) FROM automation.notification_workflow_runs WHERE state IN ('requested','executing')),
 'uncertain',(SELECT count(*) FROM automation.notification_intents WHERE status='submission_uncertain'),
 'oldest_due_seconds',(SELECT extract(epoch FROM clock_timestamp()-min(scheduled_at)) FROM automation.notification_intents WHERE status IN ('ready','deferred','retryable_failure') AND scheduled_at<=clock_timestamp()),
 'event_backlog',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'notifications.%' AND status IN ('queued','running','retry_pending')),
 'smtp_timeouts',(SELECT count(*) FROM automation.notification_delivery_results WHERE reason='smtp_timeout'),
 'smtp_attempts',(SELECT count(*) FROM automation.notification_delivery_attempts),
 'relay_accepted',(SELECT count(*) FROM automation.notification_delivery_results WHERE status='relay_accepted'),
 'digest_pending',(SELECT count(*) FROM automation.notification_intents WHERE kind='digest' AND status IN ('deferred','ready')),
 'postfix_queue_depth',(SELECT queue_depth FROM automation.notification_transport_samples WHERE observed_at>clock_timestamp()-interval '5 minutes' ORDER BY observed_at DESC LIMIT 1),
 'postfix_queue_depth_known',EXISTS(SELECT 1 FROM automation.notification_transport_samples WHERE observed_at>clock_timestamp()-interval '5 minutes'))
$$;
GRANT EXECUTE ON FUNCTION automation.notification_metrics() TO notification,api_security;
"""
