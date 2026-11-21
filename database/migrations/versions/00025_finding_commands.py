"""Narrow authenticated finding commands, approved policies and technical observability."""

from alembic import op

revision = "00025_finding_commands"
down_revision = "00024_finding_management"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Data-preserving rollback requires reviewed backup/restore")


DDL = r"""
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable)
SELECT 'finding:'||v,'Finding '||v,'human',true,'findings_manage',true,false
FROM unnest(ARRAY['close','review:confirm','exception:approve']) v;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable)
VALUES('finding:policy:manage','Approve finding policy','human',true,NULL,true,false);
INSERT INTO security.role_permissions(role_id,permission_code)
SELECT r.id,p.code FROM security.roles r CROSS JOIN security.permissions p WHERE r.code='admin'
AND p.code IN ('finding:close','finding:review:confirm','finding:exception:approve','finding:policy:manage');
CREATE FUNCTION findings.authorize(p_session uuid,p_server uuid,p_action text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor uuid; administrative boolean;
BEGIN
 IF session_user<>'api_security' THEN RAISE EXCEPTION 'verified browser context required' USING ERRCODE='42501'; END IF;
 SELECT s.user_id INTO actor FROM security.sessions s JOIN security.users u ON u.id=s.user_id
 JOIN security.password_credentials c ON c.user_id=u.id
 WHERE s.id=p_session AND s.runtime_version=1 AND s.auth_state='authenticated' AND s.revoked_at IS NULL
 AND s.expires_at>clock_timestamp() AND s.idle_expires_at>clock_timestamp()
 AND u.status='active' AND c.revoked_at IS NULL AND c.credential_version=s.credential_version;
 IF actor IS NULL OR NOT EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.role_permissions rp ON rp.role_id=ur.role_id
 WHERE ur.user_id=actor AND rp.permission_code=p_action) THEN
 RAISE EXCEPTION 'finding access denied' USING ERRCODE='42501'; END IF;
 SELECT p.administrative INTO administrative FROM security.permissions p WHERE p.code=p_action AND p.identity_type='human';
 IF administrative AND NOT EXISTS(SELECT 1 FROM security.sessions s WHERE s.id=p_session AND s.mfa_verified_at IS NOT NULL
 AND s.reauthenticated_at>clock_timestamp()-interval '5 minutes') THEN
 RAISE EXCEPTION 'fresh verified MFA required' USING ERRCODE='42501'; END IF;
 IF p_server IS NOT NULL AND (NOT EXISTS(SELECT 1 FROM inventory.servers WHERE id=p_server AND status='active') OR
 NOT (EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id WHERE ur.user_id=actor AND r.code='admin')
 OR EXISTS(SELECT 1 FROM security.user_server_access a WHERE a.user_id=actor AND a.server_id=p_server AND a.findings_manage)))
 THEN RAISE EXCEPTION 'finding object denied' USING ERRCODE='42501'; END IF;
 RETURN actor;
END $$;
-- No direct grant: only command/policy functions invoke authorization internally.
CREATE FUNCTION findings.record_change(p_id uuid,p_kind text,p_old jsonb,p_reason text,p_correlation uuid,
 p_actor uuid DEFAULT NULL,p_session uuid DEFAULT NULL) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE f findings.findings; event automation.event_types; payload jsonb;
BEGIN
 IF session_user NOT IN ('api_security','findings_writer') THEN RAISE EXCEPTION 'finding writer required' USING ERRCODE='42501'; END IF;
 SELECT * INTO f FROM findings.findings WHERE id=p_id AND model_version=2;
 SELECT * INTO event FROM automation.event_types WHERE code='finding.'||p_kind;
 IF f.id IS NULL OR event.producer_role<>session_user THEN RAISE EXCEPTION 'finding event denied' USING ERRCODE='42501'; END IF;
 INSERT INTO findings.audit_events(finding_id,episode_id,finding_version,kind,reason,actor_user_id,actor_session_id,old_value,new_value,correlation_id)
 VALUES(f.id,f.current_episode_id,f.version,p_kind,p_reason,p_actor,p_session,p_old,to_jsonb(f),p_correlation);
 payload:=jsonb_build_object('finding_id',f.id,'server_id',f.server_id,'cve_id',f.cve_id,'episode_id',f.current_episode_id,
 'change_type',p_kind,'lifecycle_status',f.status,'matching_status',f.latest_matching_status,'priority',f.current_priority,
 'row_version',f.version,'occurred_at',clock_timestamp(),'schema_version',1,'correlation_id',p_correlation);
 PERFORM automation.emit_event(gen_random_uuid(),event.code,1,event.source,'finding',f.id::text,f.version,
 payload,'finding:'||f.id::text||':'||f.version::text||':'||p_kind,p_correlation);
END $$;
GRANT EXECUTE ON FUNCTION findings.record_change(uuid,text,jsonb,text,uuid,uuid,uuid) TO findings_writer;
CREATE FUNCTION findings.command(p_session uuid,p_id uuid,p_version bigint,p_action text,p_args jsonb,p_correlation uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE f findings.findings; old jsonb; actor uuid; kind text; e findings.exceptions; decision text; n integer;
 extra text[]; reason text; config jsonb; allowed text[]; target uuid;
BEGIN
 IF session_user<>'api_security' THEN RAISE EXCEPTION 'browser role required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(909001);
 SELECT * INTO f FROM findings.findings WHERE id=p_id AND model_version=2 FOR UPDATE;
 IF f.id IS NULL THEN RAISE EXCEPTION 'finding unavailable' USING ERRCODE='P0002'; END IF;
 actor:=findings.authorize(p_session,f.server_id,'finding:update');
 IF f.version<>p_version THEN RAISE EXCEPTION 'stale finding version' USING ERRCODE='40001'; END IF;
 reason:=btrim(p_args->>'reason');
 IF reason IS NULL OR length(reason) NOT BETWEEN 3 AND 2048 OR jsonb_typeof(p_args)<>'object' THEN
 RAISE EXCEPTION 'reason required' USING ERRCODE='22023'; END IF;
 allowed:=CASE p_action WHEN 'triage' THEN ARRAY['reason','action'] WHEN 'note' THEN ARRAY['reason','text']
 WHEN 'assign' THEN ARRAY['reason','assignee_user_id'] WHEN 'review' THEN ARRAY['reason','decision','evidence','result_id']
 WHEN 'exception_request' THEN ARRAY['reason','valid_from','valid_until','scope','risk_context']
 WHEN 'mitigation' THEN ARRAY['reason','description','evidence','scope','valid_until']
 WHEN 'exception_approve' THEN ARRAY['reason','exception_id'] WHEN 'exception_reject' THEN ARRAY['reason','exception_id']
 WHEN 'exception_revoke' THEN ARRAY['reason','exception_id'] WHEN 'close' THEN ARRAY['reason'] ELSE NULL END;
 IF allowed IS NULL OR EXISTS(SELECT 1 FROM jsonb_object_keys(p_args) k WHERE NOT k=ANY(allowed)) THEN
 RAISE EXCEPTION 'unsupported finding action fields' USING ERRCODE='22023'; END IF;
 old:=to_jsonb(f);
 IF p_action='triage' THEN
  IF p_args->>'action'='start' THEN
   IF f.status NOT IN ('open','in_progress') THEN RAISE EXCEPTION 'invalid lifecycle transition' USING ERRCODE='23514'; END IF;
   f.status:='in_progress';
  ELSIF p_args->>'action'='confirm' THEN f.review_state:='confirmed';
  ELSIF p_args->>'action'='suspect_false_positive' THEN f.review_state:='suspected_false_positive';
  ELSIF p_args->>'action' IN ('needs_review','fix_check') THEN f.review_state:='needs_review';
  ELSE RAISE EXCEPTION 'unsupported triage action' USING ERRCODE='22023'; END IF;
  IF p_args->>'action'='fix_check' THEN
   PERFORM automation.enqueue_job('findings.reevaluate',1,jsonb_build_object('finding_id',f.id),gen_random_uuid()::text,p_correlation,0,NULL,NULL,3,'finding-fix-check',false);
  END IF;
  kind:='triaged';
 ELSIF p_action='note' THEN
  IF coalesce(length(p_args->>'text'),0) NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION 'invalid note' USING ERRCODE='22023'; END IF;
  INSERT INTO findings.notes(finding_id,episode_id,actor_user_id,text,reason) VALUES(f.id,f.current_episode_id,actor,p_args->>'text',reason);
  kind:='noted';
 ELSIF p_action='assign' THEN
  target:=(p_args->>'assignee_user_id')::uuid;
  IF target IS NOT NULL AND NOT findings.assignee_eligible(target,f.server_id) THEN
   RAISE EXCEPTION 'assignee lacks current object rights' USING ERRCODE='23514'; END IF;
  INSERT INTO findings.assignments(finding_id,episode_id,assignee_user_id,actor_user_id,reason) VALUES(f.id,f.current_episode_id,target,actor,reason);
  f.assignee_user_id:=target;kind:='assigned';
 ELSIF p_action='review' THEN
  IF (p_args->>'result_id')::uuid<>f.latest_matching_result_id OR coalesce(length(p_args->>'evidence'),0) NOT BETWEEN 3 AND 4096
  OR p_args->>'decision' NOT IN ('confirmed','suspected_false_positive','confirmed_false_positive','needs_review')
  THEN RAISE EXCEPTION 'review basis mismatch' USING ERRCODE='23514'; END IF;
  IF p_args->>'decision'='confirmed_false_positive' THEN
   PERFORM findings.authorize(p_session,f.server_id,'finding:review:confirm');
   IF NOT findings.lock_current(f.latest_matching_result_id,f.matching_version) THEN RAISE EXCEPTION 'review basis stale' USING ERRCODE='23514'; END IF;
  END IF;
  INSERT INTO findings.reviews(finding_id,episode_id,result_id,decision,evidence,reason,actor_user_id)
  VALUES(f.id,f.current_episode_id,f.latest_matching_result_id,p_args->>'decision',p_args->>'evidence',reason,actor);
  f.review_state:=p_args->>'decision';kind:='reviewed';
 ELSIF p_action='mitigation' THEN
  IF coalesce(length(p_args->>'description'),0) NOT BETWEEN 3 AND 2048 OR coalesce(length(p_args->>'evidence'),0) NOT BETWEEN 3 AND 4096
  OR coalesce(length(p_args->>'scope'),0) NOT BETWEEN 3 AND 256 THEN RAISE EXCEPTION 'invalid mitigation' USING ERRCODE='22023'; END IF;
  INSERT INTO findings.mitigations(finding_id,episode_id,actor_user_id,description,evidence,scope,reason,valid_until)
  VALUES(f.id,f.current_episode_id,actor,p_args->>'description',p_args->>'evidence',p_args->>'scope',reason,(p_args->>'valid_until')::timestamptz);
  f.review_state:='mitigation_documented';kind:='mitigated';
 ELSIF p_action='exception_request' THEN
  IF (p_args->>'valid_until')::timestamptz<=clock_timestamp() OR (p_args->>'valid_until')::timestamptz<=(p_args->>'valid_from')::timestamptz
  OR p_args->>'scope' NOT IN ('basis','episode') OR coalesce(length(p_args->>'risk_context'),0) NOT BETWEEN 3 AND 2048
  THEN RAISE EXCEPTION 'invalid exception interval' USING ERRCODE='22023'; END IF;
  INSERT INTO findings.exceptions(finding_id,episode_id,result_id,requested_by,scope,reason,risk_context,valid_from,valid_until)
  VALUES(f.id,f.current_episode_id,f.latest_matching_result_id,actor,p_args->>'scope',reason,p_args->>'risk_context',
  (p_args->>'valid_from')::timestamptz,(p_args->>'valid_until')::timestamptz);
  kind:='exception_requested';
 ELSIF p_action IN ('exception_approve','exception_reject','exception_revoke') THEN
  PERFORM findings.authorize(p_session,f.server_id,'finding:exception:approve');
  SELECT * INTO e FROM findings.exceptions WHERE id=(p_args->>'exception_id')::uuid AND finding_id=f.id;
  IF e.id IS NULL THEN RAISE EXCEPTION 'exception unavailable' USING ERRCODE='P0002'; END IF;
  SELECT d.decision,d.number INTO decision,n FROM findings.exception_decisions d WHERE exception_id=e.id ORDER BY number DESC LIMIT 1;
  SELECT configuration INTO config FROM findings.policy_versions p JOIN findings.active_policy a ON a.policy_id=p.id;
  IF p_action='exception_approve' THEN
   IF decision IS NOT NULL OR e.valid_until<=clock_timestamp() OR e.episode_id<>f.current_episode_id
   OR (e.scope='basis' AND e.result_id<>f.latest_matching_result_id)
   OR (coalesce((config->>'exception_four_eyes')::boolean,false) AND e.requested_by=actor)
   THEN RAISE EXCEPTION 'exception not approvable' USING ERRCODE='23514'; END IF;
   decision:='approved';kind:='exception_approved';
  ELSIF p_action='exception_reject' THEN
   IF decision IS NOT NULL THEN RAISE EXCEPTION 'exception already decided' USING ERRCODE='23514'; END IF;
   decision:='rejected';kind:='exception_rejected';
  ELSE
   IF decision IS DISTINCT FROM 'approved' THEN RAISE EXCEPTION 'exception not approved' USING ERRCODE='23514'; END IF;
   decision:='revoked';kind:='exception_revoked';
  END IF;
  INSERT INTO findings.exception_decisions(exception_id,number,decision,actor_user_id,reason) VALUES(e.id,coalesce(n,0)+1,decision,actor,reason);
 ELSIF p_action='close' THEN
  PERFORM findings.authorize(p_session,f.server_id,'finding:close');
  IF NOT findings.lock_current(f.latest_matching_result_id,f.matching_version) OR NOT (
   (f.status='resolved' AND f.resolution_result_id=f.latest_matching_result_id AND f.latest_matching_status='not_affected')
   OR (f.review_state='confirmed_false_positive' AND EXISTS(SELECT 1 FROM findings.reviews r WHERE r.finding_id=f.id
   AND r.episode_id=f.current_episode_id AND r.result_id=f.latest_matching_result_id AND r.decision='confirmed_false_positive')))
  OR f.status='closed' THEN RAISE EXCEPTION 'close requires current resolution or scoped verified false positive' USING ERRCODE='23514'; END IF;
  SELECT p.configuration INTO config FROM findings.active_policy a JOIN findings.policy_versions p ON p.id=a.policy_id;
  IF config->>'max_snapshot_age_hours' IS NOT NULL AND NOT EXISTS(
   SELECT 1 FROM matching.result_revisions r JOIN inventory.snapshots snap ON snap.id=r.snapshot_id
   WHERE r.id=f.latest_matching_result_id AND snap.captured_at BETWEEN clock_timestamp()-make_interval(hours=>(config->>'max_snapshot_age_hours')::int) AND clock_timestamp())
  THEN RAISE EXCEPTION 'close basis exceeds approved age' USING ERRCODE='23514'; END IF;
  INSERT INTO findings.episode_closures(episode_id,result_id,policy_id,reason,closure_kind)
  SELECT f.current_episode_id,f.latest_matching_result_id,policy_id,'scoped_false_positive','false_positive' FROM findings.active_policy
  ON CONFLICT DO NOTHING;
  f.status:='closed';f.closed_at:=clock_timestamp();kind:='closed';
 END IF;
 UPDATE findings.findings SET status=f.status,review_state=f.review_state,assignee_user_id=f.assignee_user_id,
 closed_at=f.closed_at,version=version+1 WHERE id=f.id;
 PERFORM findings.record_change(f.id,kind,old,reason,p_correlation,actor,p_session);
 RETURN (SELECT to_jsonb(v) FROM findings.current_findings v WHERE id=f.id);
END $$;
GRANT EXECUTE ON FUNCTION findings.command(uuid,uuid,bigint,text,jsonb,uuid) TO api_security;
CREATE FUNCTION findings.approve_policy(p_session uuid,p_label text,p_configuration jsonb,p_reason text,p_correlation uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor uuid; id uuid;
BEGIN
 actor:=findings.authorize(p_session,NULL,'finding:policy:manage');
 IF p_configuration->>'rule_version'<>'findings-1' OR length(btrim(p_reason))<3 OR jsonb_typeof(p_configuration)<>'object'
 OR EXISTS(SELECT 1 FROM jsonb_object_keys(p_configuration) k WHERE NOT k=ANY(ARRAY['rule_version','automatic_resolution','exception_four_eyes','max_snapshot_age_hours','kev_floor','epss_high_threshold','deadlines_hours','deadline_warning_hours']))
 OR (coalesce((p_configuration->>'automatic_resolution')::boolean,false) AND NOT ((p_configuration->>'max_snapshot_age_hours')::int BETWEEN 1 AND 8760))
 THEN RAISE EXCEPTION 'invalid finding policy' USING ERRCODE='22023'; END IF;
 INSERT INTO findings.policy_versions(label,configuration,approved_by,reason) VALUES(p_label,p_configuration,actor,p_reason) RETURNING policy_versions.id INTO id;
 UPDATE findings.active_policy SET policy_id=id;
 PERFORM automation.emit_event(gen_random_uuid(),'finding.policy_changed',1,'cve-api','finding-policy',id::text,1,
 jsonb_build_object('policy_id',id,'label',p_label,'actor_user_id',actor),'finding-policy:'||id::text,p_correlation);
 PERFORM automation.enqueue_job('findings.refresh_priority',1,'{}', 'finding-policy:'||id::text,p_correlation,0,NULL,NULL,3,'findings-policy',false);
 RETURN id;
END $$;
GRANT EXECUTE ON FUNCTION findings.approve_policy(uuid,text,jsonb,text,uuid) TO api_security;
CREATE FUNCTION findings.require_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v bigint;
BEGIN
 IF NEW.model_version<>2 THEN RETURN NULL; END IF;
 SELECT version INTO v FROM findings.findings WHERE id=NEW.id;
 IF NOT EXISTS(SELECT 1 FROM findings.audit_events WHERE finding_id=NEW.id AND finding_version=v)
 THEN RAISE EXCEPTION 'finding commit requires audit at current row version' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER finding_audit_commit AFTER INSERT OR UPDATE ON findings.findings
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION findings.require_audit();
CREATE FUNCTION findings.metrics() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object(
 'findings',(SELECT count(*) FROM findings.findings WHERE model_version=2),
 'lifecycle',(SELECT coalesce(jsonb_object_agg(status,n),'{}') FROM(SELECT status,count(*) n FROM findings.findings WHERE model_version=2 GROUP BY status) x),
 'priorities',(SELECT coalesce(jsonb_object_agg(current_priority,n),'{}') FROM(SELECT current_priority,count(*) n FROM findings.findings WHERE model_version=2 GROUP BY current_priority) x),
 'episodes',(SELECT count(*) FROM findings.episodes),'observations',(SELECT count(*) FROM findings.match_observations),
 'reopened',(SELECT count(*) FROM findings.audit_events WHERE kind='reopened'),
 'stale',(SELECT count(*) FROM findings.current_findings WHERE is_stale),
 'overdue',(SELECT count(*) FROM findings.current_findings WHERE is_overdue),
 'exceptions',(SELECT count(*) FROM findings.exception_state WHERE is_active),
 'queued',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'findings.%' AND status IN ('queued','retry_pending')),
 'running',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'findings.%' AND status='running'),
 'failed',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'findings.%' AND status IN ('failed','timed_out')),
 'retries',(SELECT coalesce(sum(greatest(attempts-1,0)),0) FROM automation.jobs WHERE job_type LIKE 'findings.%'),
 'duration_ms',(SELECT coalesce(sum(a.duration_ms),0) FROM automation.job_attempts a JOIN automation.jobs j ON j.id=a.job_id WHERE j.job_type LIKE 'findings.%'),
 'outbox_backlog',(SELECT count(*) FROM automation.event_deliveries d JOIN automation.event_outbox e ON e.id=d.event_id WHERE e.event_type LIKE 'finding.%' AND d.status IN ('pending','running','retry_pending')),
 'oldest_job_seconds',(SELECT extract(epoch FROM clock_timestamp()-min(created_at)) FROM automation.jobs WHERE job_type LIKE 'findings.%' AND status IN ('queued','retry_pending')));
$$;
GRANT EXECUTE ON FUNCTION findings.metrics() TO findings_writer,api_security,reporter,status_probe;
"""
