"""vulnerabilities — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "0004_vulnerabilities"
down_revision = "0003_inventories"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
CREATE TABLE cve.sources (
 id text PRIMARY KEY CHECK(id ~ '^[a-z][a-z0-9_-]+$'), name text NOT NULL, enabled boolean NOT NULL DEFAULT true,
 homepage text, created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO cve.sources(id,name,homepage) VALUES
 ('cve_list','CVE List V5','https://www.cve.org'),('nvd','NVD','https://nvd.nist.gov'),
 ('cisa_kev','CISA KEV','https://www.cisa.gov/known-exploited-vulnerabilities-catalog'),
 ('ubuntu','Ubuntu Security','https://ubuntu.com/security'),('osv','OSV','https://osv.dev');
CREATE TABLE cve.records (
 id text PRIMARY KEY CHECK(id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'), status text NOT NULL CHECK(status IN ('published','rejected','reserved')),
 description text, published_at timestamptz, modified_at timestamptz, current_revision_id uuid,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE cve.revisions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), cve_id text NOT NULL REFERENCES cve.records(id),
 source_id text NOT NULL REFERENCES cve.sources(id), source_revision text NOT NULL,
 content_sha256 bytea NOT NULL CHECK(octet_length(content_sha256)=32), original_json jsonb NOT NULL CHECK(jsonb_typeof(original_json)='object'),
 imported_at timestamptz NOT NULL DEFAULT now(), UNIQUE(cve_id,source_id,content_sha256), UNIQUE(id,cve_id)
);
ALTER TABLE cve.records ADD CONSTRAINT current_revision_same_cve FOREIGN KEY(current_revision_id,id)
 REFERENCES cve.revisions(id,cve_id) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE cve.enrichments (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), cve_id text NOT NULL REFERENCES cve.records(id),
 source_id text NOT NULL REFERENCES cve.sources(id), source_revision text NOT NULL,
 vendor text, product text, version_ranges jsonb NOT NULL DEFAULT '[]', patch_status text, fixed_version text,
 cvss numeric(3,1) CHECK(cvss BETWEEN 0 AND 10), kev boolean, epss numeric CHECK(epss BETWEEN 0 AND 1),
 content_sha256 bytea NOT NULL CHECK(octet_length(content_sha256)=32), original_json jsonb NOT NULL,
 observed_at timestamptz NOT NULL, imported_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cve_id,source_id,content_sha256)
);
CREATE INDEX enrichments_cve_source ON cve.enrichments(cve_id,source_id,observed_at DESC);
CREATE INDEX revisions_cve_time ON cve.revisions(cve_id,imported_at DESC);
CREATE TRIGGER revisions_immutable BEFORE UPDATE OR DELETE ON cve.revisions FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TRIGGER enrichments_immutable BEFORE UPDATE OR DELETE ON cve.enrichments FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TABLE matching.runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), snapshot_id uuid NOT NULL, server_id uuid NOT NULL,
 rule_version text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,
 FOREIGN KEY(snapshot_id,server_id) REFERENCES inventory.snapshots(id,server_id), UNIQUE(id,snapshot_id,server_id),
 CHECK(completed_at IS NULL OR completed_at>=started_at)
);
CREATE TABLE matching.results (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), run_id uuid NOT NULL, snapshot_id uuid NOT NULL, server_id uuid NOT NULL,
 cve_id text NOT NULL REFERENCES cve.records(id), cve_revision_id uuid NOT NULL,
 component_identity text NOT NULL, installation_context text NOT NULL DEFAULT 'host', installed_version text NOT NULL,
 status text NOT NULL CHECK(status IN ('affected','potentially_affected','not_affected','fixed','under_investigation','not_evaluable')),
 rule_id text NOT NULL, source_id text NOT NULL REFERENCES cve.sources(id), evidence jsonb NOT NULL,
 reason text NOT NULL, evaluated_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(run_id,snapshot_id,server_id) REFERENCES matching.runs(id,snapshot_id,server_id),
 FOREIGN KEY(cve_revision_id,cve_id) REFERENCES cve.revisions(id,cve_id),
 UNIQUE(run_id,cve_id,component_identity,installation_context), UNIQUE(id,server_id,cve_id,component_identity,installation_context)
);
CREATE INDEX matching_server_cve ON matching.results(server_id,cve_id,evaluated_at DESC);
CREATE TRIGGER results_immutable BEFORE UPDATE OR DELETE ON matching.results FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TABLE findings.findings (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), server_id uuid NOT NULL REFERENCES inventory.servers(id), cve_id text NOT NULL REFERENCES cve.records(id),
 component_identity text NOT NULL, installation_context text NOT NULL DEFAULT 'host',
 status text NOT NULL DEFAULT 'open' CHECK(status IN ('open','under_review','mitigated','resolved','accepted_risk','false_positive','reopened')),
 risk_level text NOT NULL CHECK(risk_level IN ('unknown','low','medium','high','critical')),
 first_seen_at timestamptz NOT NULL DEFAULT now(), last_confirmed_at timestamptz NOT NULL DEFAULT now(),
 current_match_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 UNIQUE(server_id,cve_id,component_identity,installation_context),
 FOREIGN KEY(current_match_id,server_id,cve_id,component_identity,installation_context)
 REFERENCES matching.results(id,server_id,cve_id,component_identity,installation_context),
 CHECK(last_confirmed_at>=first_seen_at)
);
CREATE TRIGGER finding_version BEFORE UPDATE ON findings.findings FOR EACH ROW EXECUTE FUNCTION system.version_guard();
CREATE TABLE findings.status_history (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), finding_id uuid NOT NULL REFERENCES findings.findings(id),
 old_status text CHECK(old_status IN ('open','under_review','mitigated','resolved','accepted_risk','false_positive','reopened')),
 new_status text NOT NULL CHECK(new_status IN ('open','under_review','mitigated','resolved','accepted_risk','false_positive','reopened')),
 reason text NOT NULL CHECK(btrim(reason)<>''), actor_user_id uuid, matching_result_id uuid REFERENCES matching.results(id),
 changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX findings_server_status ON findings.findings(server_id,status);
CREATE INDEX finding_history ON findings.status_history(finding_id,changed_at);
CREATE TRIGGER history_immutable BEFORE UPDATE OR DELETE ON findings.status_history FOR EACH ROW EXECUTE FUNCTION system.append_only();
"""
