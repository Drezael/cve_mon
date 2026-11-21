"""Measured page-first dashboard projection; no domain row, authorization or matching changes."""

from alembic import op

revision = "00031_hardening_list_projection"
down_revision = "00030_status_monitoring"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use reviewed data-preserving backup/restore")


DDL = r"""
-- Cheap one-row-per-server keys for filters/sorting before detailed, volatile evidence views.
CREATE VIEW dashboard.server_list_index AS
 SELECT s.id,s.display_name,s.status,s.primary_group_id,s.display_order,s.environment,s.criticality,
        snap.captured_at,os.distribution
 FROM inventory.servers s
 LEFT JOIN inventory.server_current_snapshots current ON current.server_id=s.id
 LEFT JOIN inventory.snapshots snap ON snap.id=current.snapshot_id
 LEFT JOIN inventory.operating_systems os ON os.snapshot_id=snap.id;
GRANT SELECT ON dashboard.server_list_index TO api_security;
-- The additive read projection is compatible with the existing status sampler.
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 IF strpos(definition,'00030_status_monitoring')=0 THEN
   RAISE EXCEPTION 'Unexpected status sampler version';
 END IF;
 EXECUTE replace(definition,'00030_status_monitoring','00031_hardening_list_projection');
END $$;
"""
