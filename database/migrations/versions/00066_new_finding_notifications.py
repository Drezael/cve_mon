"""Notify the server owner once for a newly discovered finding through existing n8n delivery."""

from alembic import op

revision = "00066_new_finding_notifications"
down_revision = "00065_epss_workflow_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(
        r"""
INSERT INTO automation.notification_rules(rule_key,version,config,reason)
VALUES('00000000-0000-0000-0000-000000000066',1,
 '{"enabled":true,"event_types":["created"],"minimum_priority":"unrated","recipients":"server_owner","mode":"immediate","lifecycle":["open","in_progress"]}',
 'Automatically notify the server owner about newly discovered findings');
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00065_epss_workflow_integration','00066_new_finding_notifications');
END $$;
""",
        prepare=False,
    )


def downgrade() -> None:
    raise RuntimeError("Preserve notification decisions and delivery history")
