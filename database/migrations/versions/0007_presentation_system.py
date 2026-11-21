"""presentation system — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "0007_presentation_system"
down_revision = "0006_automation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
CREATE TABLE dashboard.user_preferences (
 user_id uuid PRIMARY KEY REFERENCES security.users(id), preferences jsonb NOT NULL DEFAULT '{}' CHECK(system.safe_metadata(preferences)),
 updated_at timestamptz NOT NULL DEFAULT now(), version bigint NOT NULL DEFAULT 1 CHECK(version>0)
);
CREATE TABLE system.reports (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), requested_by uuid NOT NULL REFERENCES security.users(id),
 job_id uuid REFERENCES automation.jobs(id), status text NOT NULL CHECK(status IN ('pending','running','ready','failed','expired')),
 storage_reference text, content_sha256 bytea CHECK(octet_length(content_sha256)=32), created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz,
 CHECK(expires_at IS NULL OR expires_at>created_at)
);
CREATE TABLE system.source_sync_state (
 source_id text PRIMARY KEY REFERENCES cve.sources(id), cursor jsonb NOT NULL DEFAULT '{}' CHECK(system.safe_metadata(cursor)),
 last_success_at timestamptz, last_error_code text, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE system.settings (key text PRIMARY KEY, value jsonb NOT NULL CHECK(system.safe_metadata(value)), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE system.invariant_locks (name text PRIMARY KEY);
INSERT INTO system.invariant_locks VALUES ('last_active_administrator');
CREATE VIEW system.health AS SELECT 1 AS database_ready;
"""
