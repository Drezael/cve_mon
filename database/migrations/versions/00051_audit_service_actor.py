"""Expose recorded service actors without rewriting immutable audit events."""

from alembic import op

revision = "00051_audit_service_actor"
down_revision = "00050_status_source_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use a reviewed metadata rollback; preserve audit history")


DDL = r"""
CREATE OR REPLACE VIEW dashboard.administration_audit AS
 SELECT a.id,a.occurred_at,a.actor_user_id,a.action,a.object_type,a.object_id,a.outcome,
 CASE WHEN a.actor_user_id IS NULL THEN coalesce(t.name,
   CASE WHEN a.source_role='postgres_owner' AND a.action LIKE 'workflow.%' THEN 'workflow_control' ELSE a.source_role::text END)
 END AS actor_service
 FROM security.audit_log a LEFT JOIN security.technical_principals t ON t.id=a.technical_principal_id
 UNION ALL SELECT id,occurred_at,actor_user_id,'finding.'||kind,'finding',finding_id::text,'success',
  CASE WHEN actor_user_id IS NULL THEN actor_role::text END FROM findings.audit_events
 UNION ALL SELECT id,occurred_at,actor_user_id,'notification.'||action,'notification',object_id::text,'success',
  CASE WHEN actor_user_id IS NULL THEN 'notification' END FROM automation.notification_audit
 UNION ALL SELECT id,occurred_at,actor_user_id,'status.'||action,'maintenance',object_id::text,'success',
  CASE WHEN actor_user_id IS NULL THEN 'status_probe' END FROM status.audit;
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00050_status_source_policy','00051_audit_service_actor');
END $$;
"""
