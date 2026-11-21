"""Read-only minimized dashboard projections; no domain writes or new human permissions."""

from alembic import op

revision = "00028_dashboard_reads"
down_revision = "00027_notification_commands"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use verified data-preserving backup/restore")


DDL = r"""
GRANT USAGE ON SCHEMA dashboard TO api_security;
CREATE VIEW dashboard.server_security AS
 SELECT s.id,s.display_name,s.status,s.primary_group_id,s.display_order,s.environment,s.criticality,
 latest.id AS latest_snapshot_id,latest.captured_at AS latest_captured_at,
 latest.processing_status,latest.collection_status,latest.processing_error_code,
 current.snapshot_id, snap.captured_at,snap.processed_at,snap.package_count,snap.container_count,snap.image_count,
 snap.service_count,snap.quality,os.name AS os_name,os.version AS os_version,os.distribution,os.release,os.architecture,
 k.version_raw AS kernel_version,
 (SELECT jsonb_object_agg(section,status) FROM inventory.collection_sections WHERE snapshot_id=snap.id) AS sections,
 (SELECT jsonb_agg(DISTINCT package_manager) FROM inventory.packages WHERE snapshot_id=snap.id) AS package_managers,
 (SELECT max(created_at) FROM matching.result_revisions WHERE server_id=s.id) AS last_matched_at,
 (SELECT count(*) FROM matching.current_evaluations e WHERE e.server_id=s.id) AS evaluations,
 (SELECT count(*) FROM matching.current_evaluations e WHERE e.server_id=s.id AND e.is_current) AS current_evaluations,
 (p.configuration->>'max_snapshot_age_hours')::int AS inventory_max_age_hours,
 CASE WHEN snap.id IS NULL THEN 'missing' WHEN p.configuration->>'max_snapshot_age_hours' IS NULL THEN 'not_configured'
 WHEN snap.captured_at<clock_timestamp()-make_interval(hours=>(p.configuration->>'max_snapshot_age_hours')::int) THEN 'stale' ELSE 'current' END AS inventory_freshness
 FROM inventory.servers s
 LEFT JOIN LATERAL(SELECT * FROM inventory.snapshots WHERE server_id=s.id ORDER BY captured_at DESC,id DESC LIMIT 1) latest ON true
 LEFT JOIN inventory.server_current_snapshots current ON current.server_id=s.id
 LEFT JOIN inventory.snapshots snap ON snap.id=current.snapshot_id
 LEFT JOIN inventory.operating_systems os ON os.snapshot_id=snap.id
 LEFT JOIN inventory.kernels k ON k.snapshot_id=snap.id
 CROSS JOIN findings.active_policy active JOIN findings.policy_versions p ON p.id=active.policy_id;
GRANT SELECT ON dashboard.server_security TO api_security;
"""
