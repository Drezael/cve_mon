"""Resolve audit user references to usernames without rewriting the underlying events."""

from alembic import op

revision = "00052_audit_usernames"
down_revision = "00051_audit_service_actor"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    definition = (
        driver.execute("SELECT pg_get_viewdef('dashboard.administration_audit'::regclass,true)")
        .fetchone()[0]
        .strip()
        .removesuffix(";")
    )
    # The previous projection still owns service attribution and all original IDs.
    driver.execute(
        "CREATE OR REPLACE VIEW dashboard.administration_audit AS "
        "SELECT events.*,u.username AS actor_username FROM (" + definition + ") events "
        "LEFT JOIN security.users u ON u.id=events.actor_user_id",
        prepare=False,
    )
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve audit history; use a reviewed metadata rollback")


DDL = r"""
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00051_audit_service_actor','00052_audit_usernames');
END $$;
"""
