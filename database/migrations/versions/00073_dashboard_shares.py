"""Explicit account-to-account dashboard sharing; recipients retain their own data scope."""

from alembic import op

revision = "00073_dashboard_shares"
down_revision = "00072_custom_dashboards"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve dashboard shares")


DDL = r"""
CREATE TABLE dashboard.custom_dashboard_shares(
 dashboard_id uuid NOT NULL REFERENCES dashboard.custom_dashboards(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES security.users(id) ON DELETE CASCADE,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(dashboard_id,user_id)
);
GRANT SELECT,INSERT,DELETE ON dashboard.custom_dashboard_shares TO api_security;
INSERT INTO security.audit_actions(action,writer_role) VALUES('custom_dashboard.shared','api_security');
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00072_custom_dashboards','00073_dashboard_shares');
END $$;
"""
