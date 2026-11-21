"""original identity — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "00012_original_identity"
down_revision = "00011_evidence_guards"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
ALTER TABLE inventory.snapshots ADD CONSTRAINT original_identity_matches CHECK(
 COALESCE(original_json->>'server_id'=server_id::text AND original_json->>'inventory_id'=inventory_id::text,false));
ALTER TABLE inventory.snapshots ADD CONSTRAINT original_metadata_matches CHECK(
 COALESCE(original_json->>'schema_version'=schema_version
 AND original_json->>'collection_status'=collection_status
 AND (original_json->>'captured_at')::timestamptz=captured_at,false));
ALTER TABLE inventory.snapshots ADD CHECK(schema_version='1.0');
ALTER TABLE security.roles ADD CHECK(code ~ '^[a-z][a-z0-9_]*$');
"""
