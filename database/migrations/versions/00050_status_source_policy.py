"""Derive CVE freshness from the actual central n8n source schedule."""

from alembic import op

revision = "00050_status_source_policy"
down_revision = "00049_control_status_restart"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve status observation history")


DDL = r"""
ALTER FUNCTION status.sample() RENAME TO sample_v49;
REVOKE ALL ON FUNCTION status.sample_v49() FROM status_probe;
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00049_control_status_restart','00050_status_source_policy');
END $$;
CREATE FUNCTION status.sample() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT status.sample_v49() || jsonb_build_object('source_auto_updates',cfg.auto_updates,
  'sources',coalesce((SELECT jsonb_agg(jsonb_build_object('id',s.id,
    'max_age_seconds',greatest(300,cfg.update_interval*2+300),
    'last_success',(SELECT finished_at FROM cve.import_runs r WHERE r.source_id=s.id AND r.status='completed' ORDER BY finished_at DESC LIMIT 1)))
   FROM cve.sources s WHERE s.enabled AND cfg.auto_updates AND cfg.source_config->'enabled' ? s.id),'[]'::jsonb))
 FROM automation.workflow_settings cfg WHERE singleton;
$$;
REVOKE ALL ON FUNCTION status.sample() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION status.sample() TO status_probe;
"""
