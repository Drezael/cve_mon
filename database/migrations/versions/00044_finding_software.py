"""Readable software provenance from immutable matching decisions and inventory snapshots."""

from alembic import op

revision = "00044_finding_software"
down_revision = "00043_container_software"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Restore the verified backup; preserve finding evidence")


DDL = r"""
CREATE VIEW matching.component_software AS
 SELECT r.result_id,r.component_id,r.position,
 coalesce(p.name,metadata.value->>'name',CASE WHEN r.context='running-kernel' THEN 'linux' END) AS name,
 coalesce(r.decision->>'installed_version',p.version) AS version,
 CASE WHEN r.package_id IS NOT NULL OR r.context='running-kernel' THEN 'host'
 WHEN r.context LIKE 'container:%' THEN 'container' ELSE 'unknown' END AS location,
 c.container_id,coalesce(c.name,metadata.value->>'container_name') AS container_name,
 metadata.value->>'origin' AS origin,metadata.value->>'target' AS target,
 r.decision->>'status' AS status
 FROM matching.component_results r
 LEFT JOIN inventory.packages p ON p.id=r.package_id AND p.snapshot_id=r.snapshot_id
 LEFT JOIN inventory.containers c ON c.snapshot_id=r.snapshot_id AND r.context='container:'||c.container_id
 LEFT JOIN LATERAL (
  SELECT e->'component' AS value FROM jsonb_array_elements(r.decision->'evidence') e
  WHERE jsonb_typeof(e->'component')='object' LIMIT 1
 ) metadata ON true;
REVOKE ALL ON matching.component_software FROM PUBLIC;
GRANT SELECT ON matching.component_software TO api_security,reporter;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00043_container_software','00044_finding_software');
END $$;
"""
