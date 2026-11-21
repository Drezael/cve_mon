"""Coalesce concurrent CVE update correlations into one pending server report."""

from alembic import op

revision = "00068_server_report_batches"
down_revision = "00067_server_mail_reports"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(
        r"""
CREATE TABLE automation.mail_report_contexts(
 report_id uuid NOT NULL REFERENCES automation.mail_reports(id) ON DELETE CASCADE,
 correlation_id uuid NOT NULL,PRIMARY KEY(report_id,correlation_id)
);
GRANT SELECT,INSERT ON automation.mail_report_contexts TO notification;
""",
        prepare=False,
    )
    definition = driver.execute(
        "SELECT pg_get_functiondef('automation.mail_report_barrier(uuid)'::regprocedure)"
    ).fetchone()[0]
    definition = definition.replace(
        "contexts AS MATERIALIZED (\n SELECT correlation_id FROM report",
        "tracked AS MATERIALIZED (SELECT correlation_id FROM report UNION SELECT correlation_id FROM automation.mail_report_contexts WHERE report_id=p_report),\ncontexts AS MATERIALIZED (\n SELECT correlation_id FROM tracked",
    ).replace(
        "JOIN report r ON r.correlation_id=j.correlation_id",
        "JOIN tracked r ON r.correlation_id=j.correlation_id",
    )
    assert "tracked AS MATERIALIZED" in definition
    driver.execute(definition, prepare=False)
    driver.execute(
        r"""
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00067_server_mail_reports','00068_server_report_batches');
END $$;
""",
        prepare=False,
    )


def downgrade() -> None:
    raise RuntimeError("Preserve scan report grouping and completed delivery receipts")
