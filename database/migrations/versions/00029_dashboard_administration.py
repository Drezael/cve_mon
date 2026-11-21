"""Bounded administrative audit and processing reads; existing mutation rules remain intact."""

from alembic import op

revision = "00029_dashboard_administration"
down_revision = "00028_dashboard_reads"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use verified data-preserving backup/restore")


DDL = r"""
CREATE VIEW dashboard.administration_audit AS
 SELECT id,occurred_at,actor_user_id,action,object_type,object_id,outcome FROM security.audit_log
 UNION ALL SELECT id,occurred_at,actor_user_id,'finding.'||kind,'finding',finding_id::text,'success' FROM findings.audit_events
 UNION ALL SELECT id,occurred_at,actor_user_id,'notification.'||action,'notification',object_id::text,'success' FROM automation.notification_audit;
GRANT SELECT ON dashboard.administration_audit,inventory.processing_status TO api_security;
"""
