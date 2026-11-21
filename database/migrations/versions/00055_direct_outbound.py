"""Retire the outbound proxy while preserving settings and historical status evidence."""

from alembic import op

revision = "00055_direct_outbound"
down_revision = "00054_personal_smtp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use a reviewed forward deployment; preserve SMTP settings and history")


DDL = r"""
ALTER TABLE status.entities ADD COLUMN enabled boolean NOT NULL DEFAULT true;
UPDATE status.entities SET enabled=false WHERE id='envoy';
UPDATE status.entities SET dependencies=array_remove(dependencies,'envoy') WHERE 'envoy'=ANY(dependencies);
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00054_personal_smtp','00055_direct_outbound');
 SELECT pg_get_functiondef('automation.request_smtp_scoped(uuid,uuid,uuid,bigint,jsonb,text,bytea)'::regprocedure) INTO d;
 EXECUTE replace(d,'IF p_owner IS NOT NULL THEN INSERT INTO automation.smtp_routes(owner_id) VALUES(p_owner) ON CONFLICT DO NOTHING; END IF;','');
END $$;
"""
