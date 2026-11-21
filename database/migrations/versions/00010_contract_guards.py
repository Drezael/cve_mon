"""contract guards — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "00010_contract_guards"
down_revision = "0009_permission_seed"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
ALTER TABLE security.users ADD auth_version bigint NOT NULL DEFAULT 1 CHECK(auth_version>0), ADD archived_at timestamptz;
ALTER TABLE security.users ADD CHECK((status='archived')=(archived_at IS NOT NULL));
ALTER TABLE security.password_credentials ADD parameters_version integer NOT NULL DEFAULT 1 CHECK(parameters_version>0);
ALTER TABLE security.sessions ADD csrf_verifier bytea NOT NULL CHECK(octet_length(csrf_verifier)=32),
 ADD auth_version bigint NOT NULL CHECK(auth_version>0), ADD origin text NOT NULL,
 ADD last_seen_at timestamptz NOT NULL DEFAULT now(), ADD idle_expires_at timestamptz NOT NULL,
 ADD CHECK(idle_expires_at>created_at AND idle_expires_at<=expires_at);
ALTER TABLE security.mfa_methods ADD last_used_step bigint CHECK(last_used_step>=0);
ALTER TABLE security.account_tokens ADD issued_by uuid REFERENCES security.users(id);
ALTER TABLE security.technical_principals ADD certificate_san text UNIQUE, ADD version bigint NOT NULL DEFAULT 1 CHECK(version>0);
ALTER TABLE security.api_tokens ADD key_id text NOT NULL, ADD scope text NOT NULL DEFAULT 'inventory:submit' CHECK(scope='inventory:submit');
ALTER TABLE security.login_events ADD attempt_name_hash bytea CHECK(octet_length(attempt_name_hash)=32), ADD source_ip_redacted inet;
ALTER TABLE inventory.upload_receipts ADD certificate_reference text;
ALTER TABLE inventory.server_group_memberships ADD actor_id uuid REFERENCES security.users(id);
ALTER TABLE dashboard.order_versions ADD updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE system.invariant_locks ADD version bigint NOT NULL DEFAULT 1 CHECK(version>0);
ALTER TABLE system.source_sync_state ADD etag text, ADD last_attempt_at timestamptz;
ALTER TABLE system.reports ADD authorized_server_ids uuid[] NOT NULL, ADD format text NOT NULL CHECK(format IN ('json','csv')),
 ADD content bytea, ADD completed_at timestamptz;
ALTER TABLE automation.jobs ADD entity_id uuid, ADD actor_user_id uuid REFERENCES security.users(id),
 ADD actor_reference text NOT NULL DEFAULT 'system';
ALTER TABLE automation.jobs DROP CONSTRAINT jobs_job_type_idempotency_key_key;
ALTER TABLE automation.jobs ADD UNIQUE(job_type,actor_reference,idempotency_key);
ALTER TABLE automation.event_outbox ADD correlation_id uuid;
ALTER TABLE automation.notification_deliveries DROP CONSTRAINT notification_deliveries_status_check;
ALTER TABLE automation.notification_deliveries ADD CHECK(status IN ('pending','sent','accepted','bounced','failed')),
 ADD message_id text, ADD attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0), ADD updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE inventory.snapshots ADD CHECK(content_sha256=sha256(original_bytes)),
 ADD CHECK(original_json=convert_from(original_bytes,'UTF8')::jsonb);
ALTER TABLE inventory.server_groups ADD CONSTRAINT unique_group_position UNIQUE(sort_order) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE inventory.server_group_memberships ADD CONSTRAINT unique_member_position UNIQUE(group_id,display_order) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE dashboard.ungrouped_server_order ADD CONSTRAINT unique_ungrouped_position UNIQUE(display_order) DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION inventory.require_complete_sections() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE snapshot uuid;
BEGIN
 IF TG_TABLE_NAME='snapshots' THEN snapshot:=NEW.id; ELSE snapshot:=COALESCE(NEW.snapshot_id,OLD.snapshot_id); END IF;
 IF EXISTS(SELECT 1 FROM inventory.snapshots WHERE id=snapshot AND collection_status='complete' AND processing_status='processed')
 AND (SELECT count(*) FROM inventory.collection_sections WHERE snapshot_id=snapshot AND status='complete')<>4 THEN
 RAISE EXCEPTION 'complete processed inventory needs four complete sections' USING ERRCODE='23514';
 END IF; RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER snapshot_complete AFTER INSERT OR UPDATE ON inventory.snapshots DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION inventory.require_complete_sections();
CREATE CONSTRAINT TRIGGER sections_complete AFTER INSERT OR UPDATE OR DELETE ON inventory.collection_sections DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION inventory.require_complete_sections();
REVOKE SELECT ON security.api_tokens FROM api_ingest;
CREATE FUNCTION security.authorize_upload(token_verifier bytea, target_server uuid, certificate_identity text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT p.id FROM security.api_tokens t JOIN security.technical_principals p ON p.id=t.principal_id
 JOIN security.principal_server_access a ON a.principal_id=p.id
 WHERE t.verifier=token_verifier AND t.revoked_at IS NULL AND t.expires_at>now()
 AND p.status='active' AND p.certificate_san=certificate_identity AND a.server_id=target_server
$$;
GRANT EXECUTE ON FUNCTION security.authorize_upload(bytea,uuid,text) TO api_ingest;
GRANT UPDATE(auth_version,archived_at) ON security.users TO api_security;
GRANT UPDATE(parameters_version) ON security.password_credentials TO api_security;
GRANT UPDATE(last_seen_at,idle_expires_at) ON security.sessions TO api_security;
GRANT UPDATE(last_used_step) ON security.mfa_methods TO api_security;
GRANT UPDATE(certificate_san,version) ON security.technical_principals TO api_security;
GRANT UPDATE(updated_at) ON dashboard.order_versions TO dashboard_admin;
GRANT UPDATE(version) ON system.invariant_locks TO api_security;
GRANT UPDATE(etag,last_attempt_at) ON system.source_sync_state TO importer,enricher;
GRANT UPDATE(content,completed_at) ON system.reports TO reporter;
GRANT INSERT(entity_id,actor_user_id,actor_reference) ON automation.jobs TO api_ingest,api_security,inventory_processor,importer,enricher,matcher,event_dispatcher;
GRANT UPDATE(message_id,attempts,updated_at) ON automation.notification_deliveries TO notification;
GRANT SELECT ON inventory.servers,inventory.server_groups TO api_security;
CREATE VIEW security.notification_recipients AS SELECT id,email,display_name FROM security.users WHERE status='active';
GRANT SELECT ON security.notification_recipients TO notification;
ALTER TABLE security.audit_log DROP CONSTRAINT audit_log_source_role_check;
CREATE TABLE security.audit_actions (action text NOT NULL, writer_role name NOT NULL, PRIMARY KEY(action,writer_role));
INSERT INTO security.audit_actions SELECT code,producer_role FROM automation.event_types;
INSERT INTO security.audit_actions VALUES ('notification.sent','notification'),('preferences.changed','dashboard_preferences');
INSERT INTO security.audit_actions SELECT 'operation.denied',unnest(ARRAY['api_security','api_ingest','dashboard_admin','inventory_processor','importer','enricher','matcher','findings_writer','reporter','event_dispatcher','notification','dashboard_preferences']::name[]);
GRANT SELECT ON security.audit_actions TO api_security,api_ingest,dashboard_admin,inventory_processor,importer,enricher,matcher,findings_writer,reporter,event_dispatcher,notification,dashboard_preferences;
ALTER TABLE security.audit_log ENABLE ROW LEVEL SECURITY; ALTER TABLE security.audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_read ON security.audit_log FOR SELECT TO api_security USING(true);
CREATE POLICY audit_write ON security.audit_log FOR INSERT WITH CHECK(source_role=current_user AND EXISTS(SELECT 1 FROM security.audit_actions a WHERE a.action=audit_log.action AND a.writer_role=current_user));
CREATE POLICY audit_owner ON security.audit_log TO postgres_owner USING(true) WITH CHECK(true);
CREATE VIEW automation.outbox AS SELECT * FROM automation.event_outbox;
CREATE VIEW system.audit_events AS SELECT * FROM security.audit_log;
CREATE VIEW system.invariants AS SELECT * FROM system.invariant_locks;
CREATE VIEW system.source_sync AS SELECT * FROM system.source_sync_state;
CREATE VIEW inventory.os_observations AS SELECT * FROM inventory.operating_systems;
CREATE VIEW findings.records AS SELECT * FROM findings.findings;
CREATE VIEW findings.history AS SELECT * FROM findings.status_history;
CREATE TABLE findings.risk_assessments (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), finding_id uuid NOT NULL REFERENCES findings.findings(id),
 risk_level text NOT NULL CHECK(risk_level IN ('unknown','low','medium','high','critical')),
 rule_version text NOT NULL, evidence jsonb NOT NULL, assessed_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT,INSERT ON findings.risk_assessments TO findings_writer;
GRANT SELECT ON findings.risk_assessments TO api_reader,reporter;
CREATE TRIGGER risk_immutable BEFORE UPDATE OR DELETE ON findings.risk_assessments FOR EACH ROW EXECUTE FUNCTION system.append_only();
-- No public/preauth/session:self or internal service capabilities in human RBAC.
DELETE FROM security.role_permissions;
DELETE FROM security.permissions WHERE code IN ('public','preauth','session:self','events:deliver','health:read','inventory:submit') OR code LIKE 'jobs:%';
INSERT INTO security.permissions VALUES ('audit:read','Audit lesen') ON CONFLICT DO NOTHING;
INSERT INTO security.role_permissions SELECT r.id,p.code FROM security.roles r CROSS JOIN security.permissions p
 WHERE r.code='admin' OR (r.code='user_admin' AND p.code IN ('users:manage','roles:manage','tokens:manage','audit:read'))
 OR (r.code='security_analyst' AND p.code IN ('cve:read','inventory:read','inventory:upload:dashboard','matching:read','findings:read','findings:write','reports:read','reports:create','metrics:read'))
 OR (r.code='viewer' AND p.code IN ('cve:read','inventory:read','matching:read','findings:read','reports:read','metrics:read'))
 ON CONFLICT DO NOTHING;
"""
