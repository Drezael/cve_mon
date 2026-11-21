"""evidence guards — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "00011_evidence_guards"
down_revision = "00010_contract_guards"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
ALTER TABLE matching.results DROP CONSTRAINT results_run_id_cve_id_component_identity_installation_conte_key;
ALTER TABLE matching.results ADD CONSTRAINT match_version_evidence UNIQUE(run_id,cve_id,component_identity,installation_context,installed_version);
INSERT INTO automation.job_types(code,handler_role,producer_roles) SELECT 'findings.reconcile',handler_role,producer_roles FROM automation.job_types WHERE code='findings.update';
UPDATE automation.jobs SET job_type='findings.reconcile' WHERE job_type='findings.update';
DELETE FROM automation.job_types WHERE code='findings.update';
CREATE OR REPLACE FUNCTION inventory.require_complete_sections() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE snapshot uuid;
BEGIN
 IF TG_TABLE_NAME='snapshots' THEN snapshot:=NEW.id; ELSE snapshot:=COALESCE(NEW.snapshot_id,OLD.snapshot_id); END IF;
 IF EXISTS(SELECT 1 FROM inventory.snapshots WHERE id=snapshot AND collection_status='complete' AND processing_status='processed')
 AND (SELECT count(*) FROM inventory.collection_sections WHERE snapshot_id=snapshot AND section IN ('os','packages','services') AND status='complete')<>3 THEN
 RAISE EXCEPTION 'complete processed inventory needs complete core sections' USING ERRCODE='23514';
 END IF; RETURN NULL;
END $$;
ALTER TABLE matching.runs ADD source_set_hash bytea CHECK(octet_length(source_set_hash)=32),
 ADD status text NOT NULL DEFAULT 'running' CHECK(status IN ('running','succeeded','failed'));
ALTER TABLE matching.runs ADD UNIQUE(server_id,snapshot_id,source_set_hash,rule_version);
ALTER TABLE matching.results ADD enrichment_id uuid REFERENCES cve.enrichments(id);
ALTER TABLE findings.risk_assessments ADD source_revision_id uuid REFERENCES cve.revisions(id),
 ADD cvss_score numeric(3,1) CHECK(cvss_score BETWEEN 0 AND 10), ADD cvss_vector text, ADD kev boolean, ADD rationale text;
GRANT UPDATE(status) ON matching.runs TO matcher;
CREATE VIEW inventory.positive_partial_sections AS
 SELECT s.server_id,c.section,s.id AS snapshot_id,s.captured_at
 FROM inventory.snapshots s JOIN inventory.collection_sections c ON c.snapshot_id=s.id
 WHERE c.status='partial' AND s.processing_status='processed' AND s.collection_status='partial';
GRANT SELECT ON inventory.positive_partial_sections TO api_reader,inventory_processor,matcher,reporter;
CREATE FUNCTION dashboard.preferences_version_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.user_id<>OLD.user_id OR NEW.version<>OLD.version+1 THEN
 RAISE EXCEPTION 'invalid preference version' USING ERRCODE='40001'; END IF;
 NEW.updated_at:=clock_timestamp(); RETURN NEW;
END $$;
CREATE TRIGGER preferences_version BEFORE UPDATE ON dashboard.user_preferences FOR EACH ROW EXECUTE FUNCTION dashboard.preferences_version_guard();
CREATE FUNCTION dashboard.order_version_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.scope<>OLD.scope OR NEW.version<>OLD.version+1 THEN
 RAISE EXCEPTION 'invalid order version' USING ERRCODE='40001'; END IF;
 NEW.updated_at:=clock_timestamp(); RETURN NEW;
END $$;
CREATE TRIGGER order_version BEFORE UPDATE ON dashboard.order_versions FOR EACH ROW EXECUTE FUNCTION dashboard.order_version_guard();
"""
