"""privileges seeds — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "0008_privileges_seeds"
down_revision = "0007_presentation_system"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA inventory TO api_reader,api_ingest,dashboard_admin,inventory_processor,matcher,findings_writer,reporter;
GRANT USAGE ON SCHEMA cve TO api_reader,importer,enricher,matcher,findings_writer,reporter;
GRANT USAGE ON SCHEMA matching TO api_reader,matcher,findings_writer,reporter;
GRANT USAGE ON SCHEMA findings TO api_reader,findings_writer,reporter;
GRANT USAGE ON SCHEMA security TO api_security,api_ingest,dashboard_admin,api_reader,inventory_processor,importer,enricher,matcher,findings_writer,reporter,event_dispatcher,notification,dashboard_preferences;
GRANT USAGE ON SCHEMA dashboard TO dashboard_admin,dashboard_preferences,api_reader,reporter;
GRANT USAGE ON SCHEMA automation TO api_ingest,api_security,dashboard_admin,inventory_processor,importer,enricher,matcher,findings_writer,reporter,event_dispatcher,notification;
GRANT USAGE ON SCHEMA system TO api_reader,api_ingest,api_security,dashboard_admin,inventory_processor,importer,enricher,matcher,findings_writer,reporter,event_dispatcher,notification,status_probe,dashboard_preferences;
GRANT EXECUTE ON FUNCTION system.safe_metadata(jsonb),system.has_reserved_key(jsonb,text[]) TO api_reader,api_ingest,api_security,dashboard_admin,inventory_processor,importer,enricher,matcher,findings_writer,reporter,event_dispatcher,notification,dashboard_preferences;
GRANT SELECT ON inventory.servers,inventory.server_groups,inventory.server_group_memberships TO api_reader,api_ingest,dashboard_admin,inventory_processor,matcher,findings_writer,reporter;
GRANT INSERT ON inventory.servers,inventory.server_groups,inventory.server_group_memberships TO dashboard_admin;
GRANT UPDATE(display_name,inventory_hostname,inventory_name,description,environment,criticality,status,primary_group_id,archived_at,version) ON inventory.servers TO dashboard_admin;
GRANT UPDATE(name,description,sort_order,status,version) ON inventory.server_groups TO dashboard_admin;
GRANT UPDATE(display_order) ON inventory.server_group_memberships TO dashboard_admin;
GRANT DELETE ON inventory.server_group_memberships TO dashboard_admin;
GRANT SELECT,INSERT,UPDATE,DELETE ON dashboard.ungrouped_server_order TO dashboard_admin;
GRANT SELECT,INSERT,UPDATE ON dashboard.order_versions TO dashboard_admin;
GRANT SELECT ON dashboard.group_order,dashboard.server_order TO dashboard_admin,api_reader,reporter;
GRANT SELECT ON inventory.snapshots,inventory.collection_sections,inventory.operating_systems,inventory.packages,inventory.services,inventory.containers,inventory.current_snapshots,inventory.effective_sections TO api_reader,inventory_processor,matcher,reporter;
GRANT SELECT ON inventory.snapshots,inventory.upload_receipts TO api_ingest;
GRANT INSERT ON inventory.snapshots,inventory.upload_receipts TO api_ingest;
GRANT UPDATE(processing_status,processing_error_code,processed_at) ON inventory.snapshots TO inventory_processor;
GRANT SELECT,INSERT,UPDATE,DELETE ON inventory.collection_sections,inventory.operating_systems,inventory.packages,inventory.services,inventory.containers TO inventory_processor;
GRANT SELECT ON cve.records,cve.revisions,cve.sources,cve.enrichments TO api_reader,importer,enricher,matcher,findings_writer,reporter;
GRANT INSERT ON cve.records,cve.revisions TO importer;
GRANT UPDATE(status,description,published_at,modified_at,current_revision_id,updated_at) ON cve.records TO importer;
GRANT INSERT ON cve.enrichments TO enricher;
GRANT SELECT,INSERT ON matching.runs,matching.results TO matcher;
GRANT UPDATE(completed_at) ON matching.runs TO matcher;
GRANT SELECT ON matching.runs,matching.results TO api_reader,findings_writer,reporter;
GRANT SELECT,INSERT ON findings.findings,findings.status_history TO findings_writer;
GRANT UPDATE(status,risk_level,last_confirmed_at,current_match_id,version) ON findings.findings TO findings_writer;
GRANT SELECT ON findings.findings,findings.status_history TO api_reader,reporter;
GRANT SELECT ON security.user_directory TO dashboard_admin,api_reader;
GRANT SELECT ON security.users,security.password_credentials,security.roles,security.permissions,security.role_permissions,security.user_roles,security.user_server_access,security.user_group_access,security.sessions,security.mfa_methods,security.recovery_codes,security.account_tokens,security.technical_principals,security.api_tokens,security.principal_server_access,security.effective_server_access TO api_security;
GRANT INSERT ON security.users,security.password_credentials,security.roles,security.role_permissions,security.user_roles,security.user_server_access,security.user_group_access,security.sessions,security.mfa_methods,security.recovery_codes,security.account_tokens,security.technical_principals,security.api_tokens,security.principal_server_access TO api_security;
GRANT UPDATE(username,email,display_name,status,last_login_at,version) ON security.users TO api_security;
GRANT UPDATE(password_hash,changed_at,must_change) ON security.password_credentials TO api_security;
GRANT UPDATE(name,description) ON security.roles TO api_security;
GRANT UPDATE(can_read,can_upload,granted_by) ON security.user_server_access TO api_security;
GRANT UPDATE(can_read,granted_by) ON security.user_group_access TO api_security;
GRANT UPDATE(revoked_at,mfa_verified_at) ON security.sessions TO api_security;
GRANT UPDATE(verified_at,revoked_at) ON security.mfa_methods TO api_security;
GRANT UPDATE(used_at) ON security.recovery_codes TO api_security;
GRANT UPDATE(used_at,revoked_at) ON security.account_tokens TO api_security;
GRANT UPDATE(status) ON security.technical_principals TO api_security;
GRANT UPDATE(revoked_at) ON security.api_tokens TO api_security;
GRANT DELETE ON security.roles,security.role_permissions,security.user_roles,security.user_server_access,security.user_group_access,security.principal_server_access TO api_security;
GRANT SELECT ON security.technical_principals,security.api_tokens,security.principal_server_access,security.effective_server_access TO api_ingest;
ALTER TABLE security.roles ENABLE ROW LEVEL SECURITY; ALTER TABLE security.roles FORCE ROW LEVEL SECURITY;
CREATE POLICY roles_read ON security.roles FOR SELECT TO api_security USING(true);
CREATE POLICY roles_custom ON security.roles FOR ALL TO api_security USING(NOT is_system) WITH CHECK(NOT is_system);
CREATE POLICY roles_owner ON security.roles TO postgres_owner USING(true) WITH CHECK(true);
ALTER TABLE security.role_permissions ENABLE ROW LEVEL SECURITY; ALTER TABLE security.role_permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY permissions_read ON security.role_permissions FOR SELECT TO api_security USING(true);
CREATE POLICY permissions_custom ON security.role_permissions FOR ALL TO api_security
 USING(EXISTS(SELECT 1 FROM security.roles r WHERE r.id=role_id AND NOT r.is_system))
 WITH CHECK(EXISTS(SELECT 1 FROM security.roles r WHERE r.id=role_id AND NOT r.is_system));
CREATE POLICY permissions_owner ON security.role_permissions TO postgres_owner USING(true) WITH CHECK(true);
GRANT SELECT ON automation.job_types,automation.event_types TO api_ingest,api_security,dashboard_admin,inventory_processor,importer,enricher,matcher,findings_writer,reporter,event_dispatcher,notification;
GRANT SELECT ON automation.jobs TO api_ingest,api_security,inventory_processor,importer,enricher,matcher,findings_writer,reporter,event_dispatcher,notification;
GRANT INSERT(job_type,priority,scheduled_at,max_attempts,payload,idempotency_key) ON automation.jobs TO api_ingest,api_security,inventory_processor,importer,enricher,matcher,event_dispatcher;
GRANT UPDATE(status,attempts,started_at,finished_at,lease_owner,lease_until,fencing_token,error_code,result_reference,scheduled_at) ON automation.jobs TO inventory_processor,importer,enricher,matcher,findings_writer,reporter,notification;
ALTER TABLE automation.jobs ENABLE ROW LEVEL SECURITY; ALTER TABLE automation.jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY jobs_read ON automation.jobs FOR SELECT USING(EXISTS(SELECT 1 FROM automation.job_types t WHERE t.code=job_type AND (t.handler_role=current_user OR current_user=ANY(t.producer_roles))));
CREATE POLICY jobs_produce ON automation.jobs FOR INSERT WITH CHECK(EXISTS(SELECT 1 FROM automation.job_types t WHERE t.code=job_type AND current_user=ANY(t.producer_roles)));
CREATE POLICY jobs_handle ON automation.jobs FOR UPDATE USING(EXISTS(SELECT 1 FROM automation.job_types t WHERE t.code=job_type AND t.handler_role=current_user)) WITH CHECK(EXISTS(SELECT 1 FROM automation.job_types t WHERE t.code=job_type AND t.handler_role=current_user));
CREATE POLICY jobs_owner ON automation.jobs TO postgres_owner USING(true) WITH CHECK(true);
GRANT SELECT,INSERT ON automation.job_attempts TO inventory_processor,importer,enricher,matcher,findings_writer,reporter,notification;
GRANT UPDATE(finished_at,outcome,error_code) ON automation.job_attempts TO inventory_processor,importer,enricher,matcher,findings_writer,reporter,notification;
ALTER TABLE automation.job_attempts ENABLE ROW LEVEL SECURITY; ALTER TABLE automation.job_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY attempts_handler ON automation.job_attempts USING(EXISTS(SELECT 1 FROM automation.jobs j JOIN automation.job_types t ON t.code=j.job_type WHERE j.id=job_id AND t.handler_role=current_user)) WITH CHECK(EXISTS(SELECT 1 FROM automation.jobs j JOIN automation.job_types t ON t.code=j.job_type WHERE j.id=job_id AND t.handler_role=current_user));
CREATE POLICY attempts_owner ON automation.job_attempts TO postgres_owner USING(true) WITH CHECK(true);
GRANT SELECT,INSERT ON automation.event_outbox TO api_ingest,api_security,dashboard_admin,inventory_processor,importer,enricher,matcher,findings_writer,reporter;
GRANT SELECT ON automation.event_outbox TO event_dispatcher,notification;
ALTER TABLE automation.event_outbox ENABLE ROW LEVEL SECURITY; ALTER TABLE automation.event_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY events_read ON automation.event_outbox FOR SELECT USING(current_user IN ('event_dispatcher','notification') OR EXISTS(SELECT 1 FROM automation.event_types t WHERE t.code=event_type AND t.producer_role=current_user));
CREATE POLICY events_produce ON automation.event_outbox FOR INSERT WITH CHECK(EXISTS(SELECT 1 FROM automation.event_types t WHERE t.code=event_type AND t.producer_role=current_user AND t.source=event_outbox.source));
CREATE POLICY events_owner ON automation.event_outbox TO postgres_owner USING(true) WITH CHECK(true);
GRANT SELECT,INSERT ON automation.event_deliveries TO event_dispatcher;
GRANT UPDATE(status,attempts,next_attempt_at,lease_owner,lease_until,fencing_token,delivered_at,last_error_code) ON automation.event_deliveries TO event_dispatcher;
GRANT SELECT,INSERT ON automation.notification_deliveries TO notification;
GRANT UPDATE(status,error_code) ON automation.notification_deliveries TO notification;
GRANT INSERT ON security.audit_log TO api_security,api_ingest,dashboard_admin,inventory_processor,importer,enricher,matcher,findings_writer,reporter,event_dispatcher,notification,dashboard_preferences;
GRANT INSERT ON security.login_events,security.user_events TO api_security;
GRANT SELECT ON security.audit_log,security.login_events,security.user_events TO api_security;
GRANT SELECT,INSERT ON dashboard.user_preferences TO dashboard_preferences;
GRANT UPDATE(preferences,updated_at,version) ON dashboard.user_preferences TO dashboard_preferences;
GRANT SELECT,INSERT ON system.reports TO reporter;
GRANT UPDATE(status,storage_reference,content_sha256,expires_at) ON system.reports TO reporter;
GRANT SELECT ON system.reports TO api_reader;
GRANT SELECT,INSERT,UPDATE ON system.source_sync_state TO importer,enricher;
ALTER TABLE system.source_sync_state ENABLE ROW LEVEL SECURITY; ALTER TABLE system.source_sync_state FORCE ROW LEVEL SECURITY;
CREATE POLICY sync_handler ON system.source_sync_state USING((source_id='cve_list' AND current_user='importer') OR (source_id<>'cve_list' AND current_user='enricher')) WITH CHECK((source_id='cve_list' AND current_user='importer') OR (source_id<>'cve_list' AND current_user='enricher'));
CREATE POLICY sync_owner ON system.source_sync_state TO postgres_owner USING(true) WITH CHECK(true);
GRANT SELECT ON system.health TO status_probe;
GRANT SELECT ON system.invariant_locks TO api_security;
GRANT UPDATE(name) ON system.invariant_locks TO api_security;
INSERT INTO security.roles(code,name,is_system) VALUES
 ('admin','Administrator',true),('user_admin','Benutzeradministrator',true),('security_analyst','Security Analyst',true),('viewer','Viewer',true)
 ON CONFLICT(code) DO NOTHING;
"""
