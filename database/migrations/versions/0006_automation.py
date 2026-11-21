"""automation — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "0006_automation"
down_revision = "0005_identities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
CREATE TABLE automation.job_types (code text PRIMARY KEY, handler_role name NOT NULL, producer_roles name[] NOT NULL);
INSERT INTO automation.job_types VALUES
 ('inventory.process','inventory_processor',ARRAY['api_ingest']::name[]),
 ('cve.import','importer',ARRAY['api_security']::name[]),
 ('cve.enrich','enricher',ARRAY['importer','api_security']::name[]),
 ('matching.run','matcher',ARRAY['inventory_processor','enricher','api_security']::name[]),
 ('findings.update','findings_writer',ARRAY['matcher']::name[]),
 ('report.generate','reporter',ARRAY['api_security']::name[]),
 ('notification.send','notification',ARRAY['event_dispatcher']::name[]);
CREATE TABLE automation.jobs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), job_type text NOT NULL REFERENCES automation.job_types(code),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','queued','running','succeeded','failed','retry_pending','cancelled','timed_out')),
 priority integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(), scheduled_at timestamptz NOT NULL DEFAULT now(),
 started_at timestamptz, finished_at timestamptz, max_attempts integer NOT NULL DEFAULT 3 CHECK(max_attempts BETWEEN 1 AND 100),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0 AND attempts<=max_attempts), lease_owner uuid, lease_until timestamptz,
 fencing_token bigint NOT NULL DEFAULT 0 CHECK(fencing_token>=0), error_code text, result_reference uuid,
 payload jsonb NOT NULL DEFAULT '{}' CHECK(system.safe_metadata(payload)), idempotency_key text NOT NULL,
 UNIQUE(job_type,idempotency_key), CHECK((status='running')=(lease_owner IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK((lease_owner IS NULL)=(lease_until IS NULL)), CHECK(finished_at IS NULL OR finished_at>=created_at)
);
CREATE TABLE automation.job_attempts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), job_id uuid NOT NULL REFERENCES automation.jobs(id), attempt integer NOT NULL CHECK(attempt>0),
 fencing_token bigint NOT NULL CHECK(fencing_token>0), worker_id uuid NOT NULL, started_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz, outcome text CHECK(outcome IN ('succeeded','failed','timed_out','cancelled')), error_code text,
 UNIQUE(job_id,attempt), UNIQUE(job_id,fencing_token), CHECK(finished_at IS NULL OR finished_at>=started_at)
);
CREATE INDEX jobs_queue ON automation.jobs(job_type,priority DESC,scheduled_at,id) WHERE status IN ('pending','queued','retry_pending','running');
CREATE TABLE automation.event_types (code text PRIMARY KEY, producer_role name NOT NULL, source text NOT NULL);
INSERT INTO automation.event_types VALUES
 ('inventory.accepted','api_ingest','inventory-api'),('inventory.processed','inventory_processor','inventory-processor'),
 ('cve.imported','importer','cve-importer'),('cve.enriched','enricher','cve-enricher'),
 ('matching.completed','matcher','matching-engine'),('finding.changed','findings_writer','finding-manager'),
 ('report.ready','reporter','reporting'),('security.changed','api_security','security-api'),
 ('administration.changed','dashboard_admin','administration-api');
CREATE TABLE automation.event_outbox (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), event_type text NOT NULL REFERENCES automation.event_types(code),
 source text NOT NULL, aggregate_type text NOT NULL, aggregate_id text NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now(),
 payload jsonb NOT NULL CHECK(system.safe_metadata(payload)), idempotency_key text NOT NULL, UNIQUE(source,idempotency_key)
);
CREATE TABLE automation.event_deliveries (
 event_id uuid NOT NULL REFERENCES automation.event_outbox(id), destination text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','delivered','retry_pending','failed')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0), next_attempt_at timestamptz NOT NULL DEFAULT now(),
 lease_owner uuid, lease_until timestamptz, fencing_token bigint NOT NULL DEFAULT 0 CHECK(fencing_token>=0),
 delivered_at timestamptz, last_error_code text, PRIMARY KEY(event_id,destination),
 CHECK((status='running')=(lease_owner IS NOT NULL AND lease_until IS NOT NULL)), CHECK((lease_owner IS NULL)=(lease_until IS NULL))
);
CREATE TABLE automation.notification_deliveries (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), event_id uuid NOT NULL REFERENCES automation.event_outbox(id),
 recipient_user_id uuid NOT NULL REFERENCES security.users(id), channel text NOT NULL,
 status text NOT NULL CHECK(status IN ('pending','sent','failed')), error_code text, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(event_id,recipient_user_id,channel)
);
CREATE INDEX deliveries_queue ON automation.event_deliveries(status,next_attempt_at,event_id) WHERE status<>'delivered';
CREATE TRIGGER outbox_immutable BEFORE UPDATE OR DELETE ON automation.event_outbox FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TABLE security.audit_log (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), occurred_at timestamptz NOT NULL DEFAULT now(),
 actor_user_id uuid REFERENCES security.users(id), technical_principal_id uuid REFERENCES security.technical_principals(id),
 source_role name NOT NULL DEFAULT current_user, action text NOT NULL, object_type text NOT NULL, object_id text,
 request_id uuid, outcome text NOT NULL CHECK(outcome IN ('success','failure','denied')), metadata jsonb NOT NULL DEFAULT '{}' CHECK(system.safe_metadata(metadata)),
 CHECK(source_role=current_user)
);
CREATE TABLE security.login_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid REFERENCES security.users(id), occurred_at timestamptz NOT NULL DEFAULT now(),
 outcome text NOT NULL CHECK(outcome IN ('success','failure','locked','denied')), request_id uuid, reason_code text NOT NULL,
 metadata jsonb NOT NULL DEFAULT '{}' CHECK(system.safe_metadata(metadata))
);
CREATE TABLE security.user_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES security.users(id), actor_user_id uuid REFERENCES security.users(id),
 occurred_at timestamptz NOT NULL DEFAULT now(), event_type text NOT NULL, metadata jsonb NOT NULL DEFAULT '{}' CHECK(system.safe_metadata(metadata))
);
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON security.audit_log FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TRIGGER login_events_immutable BEFORE UPDATE OR DELETE ON security.login_events FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TRIGGER user_events_immutable BEFORE UPDATE OR DELETE ON security.user_events FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE INDEX audit_time ON security.audit_log(occurred_at DESC,id);
"""
