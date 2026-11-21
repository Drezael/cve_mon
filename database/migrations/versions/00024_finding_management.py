"""Stable server/CVE findings, immutable observations, episodes and approved policies."""

from alembic import op

revision = "00024_finding_management"
down_revision = "00023_matching_engine"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Data-preserving rollback requires reviewed backup/restore")


DDL = r"""
GRANT USAGE ON SCHEMA findings,matching,cve TO api_security;
-- Existing component findings stay model 1. No legacy identity is deleted or reinterpreted.
ALTER TABLE findings.findings DROP CONSTRAINT findings_cve_id_fkey,
 DROP CONSTRAINT findings_status_check,
 ALTER component_identity DROP NOT NULL, ALTER installation_context DROP NOT NULL,
 ALTER current_match_id DROP NOT NULL, ALTER last_confirmed_at DROP NOT NULL,
 ADD model_version integer NOT NULL DEFAULT 1 CHECK(model_version IN (1,2)),
 ADD legacy_cve_id text GENERATED ALWAYS AS (CASE WHEN model_version=1 THEN cve_id END) STORED REFERENCES cve.records(id),
 ADD enrichment_identity text REFERENCES cve.enrichment_identities(identity),
 ADD latest_matching_result_id uuid, ADD latest_matching_status text,
 ADD matching_version bigint NOT NULL DEFAULT 0 CHECK(matching_version>=0),
 ADD current_episode_id uuid, ADD last_evaluated_at timestamptz,
 ADD resolved_at timestamptz, ADD closed_at timestamptz,
 ADD resolution_result_id uuid REFERENCES matching.result_revisions(id),
 ADD current_priority text NOT NULL DEFAULT 'unrated' CHECK(current_priority IN ('critical','high','medium','low','unrated')),
 ADD assignee_user_id uuid REFERENCES security.users(id),
 ADD review_state text NOT NULL DEFAULT 'unreviewed' CHECK(review_state IN ('unreviewed','needs_review','confirmed','suspected_false_positive','confirmed_false_positive','mitigation_documented')),
 ADD priority_basis jsonb, ADD priority_fingerprint bytea,
 ADD current_deadline_id uuid,
 ADD FOREIGN KEY(resolution_result_id,server_id,cve_id) REFERENCES matching.result_revisions(id,server_id,identity),
 ADD FOREIGN KEY(latest_matching_result_id,server_id,cve_id) REFERENCES matching.result_revisions(id,server_id,identity),
 ADD CHECK((model_version=1 AND current_match_id IS NOT NULL AND component_identity IS NOT NULL
 AND status IN ('open','under_review','mitigated','resolved','accepted_risk','false_positive','reopened'))
 OR (model_version=2 AND enrichment_identity IS NOT NULL AND enrichment_identity=cve_id AND cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
 AND latest_matching_result_id IS NOT NULL AND matching_version>0
 AND latest_matching_status IN ('affected','potentially_affected','not_affected','unknown','not_applicable')
 AND status IN ('open','in_progress','resolved','closed')
 AND (status<>'resolved' OR (resolved_at IS NOT NULL AND resolution_result_id IS NOT NULL))
 AND (status<>'closed' OR closed_at IS NOT NULL)));
CREATE UNIQUE INDEX finding_stable_identity ON findings.findings(server_id,cve_id) WHERE model_version=2;
CREATE INDEX findings_identity ON findings.findings(cve_id,id) WHERE model_version=2;
CREATE INDEX findings_priority ON findings.findings(current_priority,status,id) WHERE model_version=2;
CREATE INDEX findings_assignee ON findings.findings(assignee_user_id,id) WHERE model_version=2;
CREATE TABLE findings.policy_versions(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), label text NOT NULL UNIQUE CHECK(label ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'),
 configuration jsonb NOT NULL CHECK(jsonb_typeof(configuration)='object'),
 approved_by uuid REFERENCES security.users(id), reason text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp());
INSERT INTO findings.policy_versions(id,label,configuration,reason) VALUES
('00000000-0000-4000-8000-000000000018','findings-1-default',
'{"rule_version":"findings-1","automatic_resolution":false,"max_snapshot_age_hours":null,"kev_floor":"high","epss_high_threshold":null,"deadlines_hours":{},"deadline_warning_hours":null}',
'Initial conservative policy; no automatic resolution or operator SLA');
CREATE TABLE findings.active_policy(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),policy_id uuid NOT NULL REFERENCES findings.policy_versions(id));
INSERT INTO findings.active_policy VALUES(true,'00000000-0000-4000-8000-000000000018');
CREATE TABLE findings.episodes(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),finding_id uuid NOT NULL REFERENCES findings.findings(id),
 number integer NOT NULL CHECK(number>0),opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 first_result_id uuid NOT NULL REFERENCES matching.result_revisions(id),reopening_reason text,
 UNIQUE(finding_id,number),UNIQUE(id,finding_id));
ALTER TABLE findings.findings ADD FOREIGN KEY(current_episode_id,id) REFERENCES findings.episodes(id,finding_id) DEFERRABLE INITIALLY DEFERRED,
 ADD CHECK(model_version=1 OR current_episode_id IS NOT NULL);
CREATE TABLE findings.episode_closures(
 episode_id uuid PRIMARY KEY REFERENCES findings.episodes(id),result_id uuid NOT NULL REFERENCES matching.result_revisions(id),
 closed_at timestamptz NOT NULL DEFAULT clock_timestamp(),policy_id uuid NOT NULL REFERENCES findings.policy_versions(id),reason text NOT NULL,
 closure_kind text NOT NULL DEFAULT 'technical_fix' CHECK(closure_kind IN ('technical_fix','false_positive')));
CREATE TABLE findings.match_observations(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),finding_id uuid NOT NULL REFERENCES findings.findings(id),
 episode_id uuid,result_id uuid NOT NULL REFERENCES matching.result_revisions(id),
 publication_version bigint NOT NULL CHECK(publication_version>0),is_historical boolean NOT NULL,
 snapshot_captured_at timestamptz NOT NULL,matched_at timestamptz NOT NULL,observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(episode_id,finding_id) REFERENCES findings.episodes(id,finding_id),UNIQUE(finding_id,publication_version));
CREATE INDEX finding_observations ON findings.match_observations(finding_id,observed_at,id);
CREATE TABLE findings.event_receipts(
 event_id uuid PRIMARY KEY REFERENCES automation.event_outbox(id),job_id uuid NOT NULL REFERENCES automation.jobs(id),
 result_id uuid REFERENCES matching.result_revisions(id),finding_id uuid REFERENCES findings.findings(id),
 outcome text NOT NULL CHECK(outcome IN ('applied','duplicate','stale','no_candidate')),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE findings.audit_events(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),finding_id uuid NOT NULL REFERENCES findings.findings(id),
 episode_id uuid NOT NULL REFERENCES findings.episodes(id),finding_version bigint NOT NULL,
 kind text NOT NULL CHECK(kind ~ '^[a-z_]{1,64}$'),reason text NOT NULL,
 actor_user_id uuid REFERENCES security.users(id),actor_session_id uuid REFERENCES security.sessions(id),
 actor_role name NOT NULL DEFAULT session_user,old_value jsonb NOT NULL,new_value jsonb NOT NULL,
 correlation_id uuid NOT NULL,occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((actor_role='findings_writer' AND actor_user_id IS NULL AND actor_session_id IS NULL)
 OR (actor_role='api_security' AND actor_user_id IS NOT NULL AND actor_session_id IS NOT NULL)),
 UNIQUE(finding_id,finding_version,kind));
CREATE INDEX finding_audit_timeline ON findings.audit_events(finding_id,occurred_at DESC,id DESC);
CREATE VIEW findings.state_history AS SELECT id,finding_id,episode_id,kind,reason,old_value->>'status' AS old_status,
 new_value->>'status' AS new_status,actor_user_id,actor_role,occurred_at FROM findings.audit_events;
CREATE TABLE findings.notes(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),finding_id uuid NOT NULL REFERENCES findings.findings(id),episode_id uuid NOT NULL,
 actor_user_id uuid NOT NULL REFERENCES security.users(id),text text NOT NULL CHECK(length(text) BETWEEN 1 AND 4096),
 reason text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(episode_id,finding_id) REFERENCES findings.episodes(id,finding_id));
CREATE TABLE findings.assignments(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),finding_id uuid NOT NULL REFERENCES findings.findings(id),episode_id uuid NOT NULL,
 assignee_user_id uuid REFERENCES security.users(id),actor_user_id uuid NOT NULL REFERENCES security.users(id),reason text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),FOREIGN KEY(episode_id,finding_id) REFERENCES findings.episodes(id,finding_id));
CREATE TABLE findings.reviews(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),finding_id uuid NOT NULL REFERENCES findings.findings(id),episode_id uuid NOT NULL,
 result_id uuid NOT NULL REFERENCES matching.result_revisions(id),decision text NOT NULL,
 evidence text NOT NULL,reason text NOT NULL,actor_user_id uuid NOT NULL REFERENCES security.users(id),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(decision IN ('confirmed','suspected_false_positive','confirmed_false_positive','needs_review')),
 FOREIGN KEY(episode_id,finding_id) REFERENCES findings.episodes(id,finding_id));
CREATE TABLE findings.exceptions(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),finding_id uuid NOT NULL REFERENCES findings.findings(id),episode_id uuid NOT NULL,
 result_id uuid NOT NULL REFERENCES matching.result_revisions(id),requested_by uuid NOT NULL REFERENCES security.users(id),
 scope text NOT NULL CHECK(scope IN ('basis','episode')),reason text NOT NULL,risk_context text NOT NULL,
 valid_from timestamptz NOT NULL,valid_until timestamptz NOT NULL CHECK(valid_until>valid_from),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),FOREIGN KEY(episode_id,finding_id) REFERENCES findings.episodes(id,finding_id));
CREATE INDEX findings_exceptions_expiry ON findings.exceptions(valid_until,id);
CREATE TABLE findings.exception_decisions(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),exception_id uuid NOT NULL REFERENCES findings.exceptions(id),
 number integer NOT NULL CHECK(number>0),decision text NOT NULL CHECK(decision IN ('approved','rejected','revoked','expired')),
 actor_user_id uuid REFERENCES security.users(id),reason text NOT NULL,decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(exception_id,number));
CREATE TABLE findings.mitigations(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),finding_id uuid NOT NULL REFERENCES findings.findings(id),episode_id uuid NOT NULL,
 actor_user_id uuid NOT NULL REFERENCES security.users(id),description text NOT NULL,evidence text NOT NULL,scope text NOT NULL,
 reason text NOT NULL,valid_until timestamptz,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(episode_id,finding_id) REFERENCES findings.episodes(id,finding_id));
CREATE TABLE findings.priority_history(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),finding_id uuid NOT NULL REFERENCES findings.findings(id),episode_id uuid NOT NULL,
 priority text NOT NULL CHECK(priority IN ('critical','high','medium','low','unrated')),
 policy_id uuid NOT NULL REFERENCES findings.policy_versions(id),signals jsonb NOT NULL,reasons jsonb NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(episode_id,finding_id) REFERENCES findings.episodes(id,finding_id));
CREATE TABLE findings.deadlines(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),finding_id uuid NOT NULL REFERENCES findings.findings(id),episode_id uuid NOT NULL,
 policy_id uuid NOT NULL REFERENCES findings.policy_versions(id),due_at timestamptz NOT NULL,anchor_at timestamptz NOT NULL,
 priority text NOT NULL,reason text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(episode_id,finding_id) REFERENCES findings.episodes(id,finding_id),UNIQUE(id,finding_id));
CREATE INDEX finding_deadline_due ON findings.deadlines(due_at,id);
ALTER TABLE findings.findings ADD FOREIGN KEY(current_deadline_id,id) REFERENCES findings.deadlines(id,finding_id) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE findings.escalations(
 deadline_id uuid NOT NULL REFERENCES findings.deadlines(id),kind text NOT NULL CHECK(kind IN ('approaching','overdue')),
 emitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(deadline_id,kind));
CREATE VIEW findings.exception_state AS
 SELECT e.*,d.decision AS decision,coalesce(d.number,0) AS decision_version,d.actor_user_id AS decided_by,
 (d.decision='approved' AND clock_timestamp()>=e.valid_from AND clock_timestamp()<e.valid_until
 AND f.current_episode_id=e.episode_id AND (e.scope='episode' OR f.latest_matching_result_id=e.result_id)) IS TRUE AS is_active
 FROM findings.exceptions e JOIN findings.findings f ON f.id=e.finding_id
 LEFT JOIN LATERAL(SELECT * FROM findings.exception_decisions d WHERE d.exception_id=e.id ORDER BY number DESC LIMIT 1) d ON true;
CREATE FUNCTION findings.assignee_eligible(p_user uuid,p_server uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM security.users u WHERE u.id=p_user AND u.status='active'
 AND EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.role_permissions rp ON rp.role_id=ur.role_id
 WHERE ur.user_id=u.id AND rp.permission_code='finding:update')
 AND (EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id WHERE ur.user_id=u.id AND r.code='admin')
 OR EXISTS(SELECT 1 FROM security.user_server_access a WHERE a.user_id=u.id AND a.server_id=p_server AND a.findings_manage)));
$$;
GRANT EXECUTE ON FUNCTION findings.assignee_eligible(uuid,uuid) TO api_security,findings_writer;
CREATE VIEW findings.current_findings AS
 SELECT f.*,s.status AS server_status,s.display_name AS server_name,s.primary_group_id,
 snap.captured_at,match.created_at AS matched_at,
 (match.id=c.result_id AND c.current_version=f.matching_version AND current.snapshot_id=match.snapshot_id
 AND enr.current_revision_id=match.enrichment_revision_id AND s.status='active') IS TRUE AS technical_is_current,
 extract(epoch FROM clock_timestamp()-snap.captured_at)/3600 AS evidence_age_hours,
 d.due_at,(d.due_at<clock_timestamp() AND f.status IN ('open','in_progress')) IS TRUE AS is_overdue,
 EXISTS(SELECT 1 FROM findings.exception_state e WHERE e.finding_id=f.id AND e.is_active) AS has_active_exception,
 findings.assignee_eligible(f.assignee_user_id,f.server_id) AS assignee_is_eligible,
 (f.last_evaluated_at IS NULL OR NOT (match.id=c.result_id AND c.current_version=f.matching_version
 AND current.snapshot_id=match.snapshot_id AND enr.current_revision_id=match.enrichment_revision_id)
 OR ((p.configuration->>'max_snapshot_age_hours') IS NOT NULL AND snap.captured_at<clock_timestamp()-make_interval(hours=>(p.configuration->>'max_snapshot_age_hours')::int))) IS TRUE AS is_stale
 FROM findings.findings f JOIN inventory.servers s ON s.id=f.server_id
 JOIN matching.result_revisions match ON match.id=f.latest_matching_result_id
 JOIN inventory.snapshots snap ON snap.id=match.snapshot_id
 LEFT JOIN matching.current_results c ON c.server_id=f.server_id AND c.identity=f.cve_id
 LEFT JOIN inventory.server_current_snapshots current ON current.server_id=f.server_id
 JOIN cve.enrichment_identities enr ON enr.identity=f.cve_id
 LEFT JOIN findings.deadlines d ON d.id=f.current_deadline_id
 CROSS JOIN findings.active_policy active JOIN findings.policy_versions p ON p.id=active.policy_id
 WHERE f.model_version=2;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['policy_versions','episodes','episode_closures','match_observations','event_receipts','audit_events','notes','assignments','reviews','exceptions','exception_decisions','mitigations','priority_history','deadlines','escalations'] LOOP
 EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON findings.%I FOR EACH ROW EXECUTE FUNCTION system.append_only()',t);
 EXECUTE format('GRANT SELECT ON findings.%I TO findings_writer,api_security,reporter',t);
 END LOOP;
END $$;
GRANT SELECT ON findings.current_findings,findings.state_history,findings.exception_state,findings.active_policy,findings.findings TO api_security,findings_writer,reporter;
GRANT INSERT ON findings.episodes,findings.episode_closures,findings.match_observations,findings.event_receipts,
 findings.audit_events,findings.priority_history,findings.deadlines,findings.escalations,findings.exception_decisions TO findings_writer;
GRANT UPDATE ON findings.findings TO findings_writer;
GRANT SELECT ON inventory.matching_snapshots,inventory.snapshots,inventory.collection_sections,
 matching.current_results,matching.current_evaluations,matching.result_revisions,matching.component_results,matching.result_evidence,
 matching.result_conflicts,matching.coverage,cve.current_enrichment,cve.enrichment_identities,cve.enrichment_revisions,
 cve.current_epss_scores,cve.epss_current_dataset TO findings_writer;
GRANT SELECT ON matching.result_revisions,matching.component_results,matching.result_evidence,matching.result_conflicts,
 matching.coverage,cve.enrichment_revisions,inventory.snapshots TO api_security;
-- Scope helpers can read security data, but the worker cannot read credentials or sessions.
CREATE FUNCTION findings.lock_current(p_result uuid,p_version bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r matching.result_revisions;
BEGIN
 IF session_user NOT IN ('findings_writer','api_security') THEN RAISE EXCEPTION 'finding context required' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM matching.result_revisions WHERE id=p_result;
 IF r.id IS NULL THEN RETURN false; END IF;
 IF NOT EXISTS(SELECT 1 FROM inventory.servers WHERE id=r.server_id AND status='active' FOR SHARE)
 OR NOT EXISTS(SELECT 1 FROM inventory.server_current_snapshots WHERE server_id=r.server_id AND snapshot_id=r.snapshot_id FOR SHARE)
 OR NOT EXISTS(SELECT 1 FROM cve.enrichment_identities WHERE identity=r.identity AND current_revision_id=r.enrichment_revision_id FOR SHARE)
 OR NOT EXISTS(SELECT 1 FROM matching.current_results WHERE server_id=r.server_id AND identity=r.identity AND result_id=r.id AND current_version=p_version FOR SHARE)
 THEN RETURN false; END IF;
 RETURN true;
END $$;
GRANT EXECUTE ON FUNCTION findings.lock_current(uuid,bigint) TO findings_writer,api_security;
CREATE FUNCTION findings.observation_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM findings.findings f JOIN matching.result_revisions r ON r.id=NEW.result_id
 WHERE f.id=NEW.finding_id AND f.server_id=r.server_id AND f.cve_id=r.identity)
 THEN RAISE EXCEPTION 'observation identity mismatch' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER observation_binding BEFORE INSERT ON findings.match_observations FOR EACH ROW EXECUTE FUNCTION findings.observation_guard();
CREATE FUNCTION findings.evidence_binding() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE fid uuid; rid uuid;
BEGIN
 IF TG_TABLE_NAME='episodes' THEN fid:=NEW.finding_id;rid:=NEW.first_result_id;
 ELSIF TG_TABLE_NAME='episode_closures' THEN SELECT finding_id INTO fid FROM findings.episodes WHERE id=NEW.episode_id;rid:=NEW.result_id;
 ELSE fid:=NEW.finding_id;rid:=NEW.result_id; END IF;
 IF NOT EXISTS(SELECT 1 FROM findings.findings f JOIN matching.result_revisions r ON r.id=rid WHERE f.id=fid AND f.server_id=r.server_id AND f.cve_id=r.identity)
 THEN RAISE EXCEPTION 'finding evidence identity mismatch' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['episodes','episode_closures','reviews','exceptions'] LOOP
 EXECUTE format('CREATE TRIGGER evidence_binding BEFORE INSERT ON findings.%I FOR EACH ROW EXECUTE FUNCTION findings.evidence_binding()',t);
 END LOOP;
END $$;
CREATE FUNCTION findings.audit_actor_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.actor_role<>session_user OR (session_user='findings_writer' AND NEW.actor_user_id IS NOT NULL)
 OR (session_user='api_security' AND NOT EXISTS(SELECT 1 FROM security.sessions s WHERE s.id=NEW.actor_session_id AND s.user_id=NEW.actor_user_id
 AND s.revoked_at IS NULL AND s.auth_state='authenticated' AND s.expires_at>clock_timestamp() AND s.idle_expires_at>clock_timestamp()))
 THEN RAISE EXCEPTION 'untrusted finding actor' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER finding_actor BEFORE INSERT ON findings.audit_events FOR EACH ROW EXECUTE FUNCTION findings.audit_actor_guard();
UPDATE automation.job_types SET runtime_seconds=3600,max_attempts=3,producer_roles=ARRAY['findings_writer','api_security','matcher','enricher']::name[] WHERE code='findings.reconcile';
INSERT INTO automation.job_types(code,handler_role,producer_roles,runtime_seconds,max_attempts)
SELECT 'findings.'||v,'findings_writer',ARRAY['findings_writer','api_security','matcher','enricher']::name[],3600,3
FROM unnest(ARRAY['consume_matching_event','refresh_priority','check_deadlines','check_exceptions','backfill','reevaluate','maintenance']) v;
INSERT INTO automation.event_types(code,producer_role,source)
SELECT 'finding.'||v,'findings_writer','cve-findings' FROM unnest(ARRAY['created','updated','confirmed_affected','potentially_affected','resolved','reopened','priority_changed','review_required','exception_expired','deadline_approaching','overdue']) v;
INSERT INTO automation.event_types(code,producer_role,source)
SELECT 'finding.'||v,'api_security','cve-api' FROM unnest(ARRAY['closed','assigned','triaged','noted','reviewed','mitigated','exception_requested','exception_approved','exception_rejected','exception_revoked','policy_changed']) v;
CREATE FUNCTION findings.schedule_event() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE kind text; payload jsonb;
BEGIN
 IF NEW.source='cve-matcher' AND NEW.event_type IN ('matching.created','matching.replaced') THEN
 kind:='findings.consume_matching_event';payload:=jsonb_build_object('event_id',NEW.id);
 ELSIF NEW.source='cve-enricher' AND NEW.event_type IN ('cve.enrichment.cvss_changed','cve.enrichment.kev_changed','cve.enrichment.epss_updated') THEN
 kind:='findings.refresh_priority';payload:=CASE WHEN NEW.payload->>'identity' ~ '^CVE-[0-9]{4}-[0-9]{4,}$' THEN jsonb_build_object('identity',NEW.payload->>'identity') ELSE '{}' END;
 ELSE RETURN NEW; END IF;
 PERFORM automation.enqueue_job(kind,1,payload,'finding-event:'||NEW.id::text,NEW.correlation_id,0,NULL,NULL,3,'findings-events',false);
 RETURN NEW;
END $$;
CREATE POLICY finding_matching_inputs ON automation.event_outbox FOR SELECT TO findings_writer
USING(source='cve-matcher' AND event_type IN ('matching.created','matching.replaced'));
CREATE TRIGGER schedule_findings AFTER INSERT ON automation.event_outbox FOR EACH ROW EXECUTE FUNCTION findings.schedule_event();
"""
