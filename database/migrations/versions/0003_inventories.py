"""inventories — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "0003_inventories"
down_revision = "0002_administration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
CREATE TABLE inventory.snapshots (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), inventory_id uuid NOT NULL UNIQUE,
 server_id uuid NOT NULL REFERENCES inventory.servers(id), schema_version text NOT NULL,
 captured_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
 collection_status text NOT NULL CHECK(collection_status IN ('complete','partial','failed')),
 content_sha256 bytea NOT NULL CHECK(octet_length(content_sha256)=32),
 original_json jsonb NOT NULL CHECK(jsonb_typeof(original_json)='object'), original_bytes bytea NOT NULL,
 processing_status text NOT NULL DEFAULT 'pending' CHECK(processing_status IN ('pending','processing','processed','failed')),
 processing_error_code text, processed_at timestamptz,
 UNIQUE(id,server_id), CHECK(octet_length(original_bytes)>0),
 CHECK(NOT system.has_reserved_key(original_json,ARRAY['groups','group_ids','primary_group_id','sort_order','display_order','display_name','criticality','environment','server_groups']))
);
CREATE FUNCTION inventory.accept_snapshot() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM inventory.servers WHERE id=NEW.server_id AND status='active' FOR SHARE) THEN
  RAISE EXCEPTION 'server not active or unknown' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER snapshot_active BEFORE INSERT ON inventory.snapshots FOR EACH ROW EXECUTE FUNCTION inventory.accept_snapshot();
CREATE FUNCTION inventory.original_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['processing_status','processing_error_code','processed_at']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['processing_status','processing_error_code','processed_at']) THEN
  RAISE EXCEPTION 'original inventory is immutable' USING ERRCODE='42501';
 END IF; RETURN NEW;
END $$;
CREATE TRIGGER snapshot_original BEFORE UPDATE ON inventory.snapshots FOR EACH ROW EXECUTE FUNCTION inventory.original_guard();
CREATE TABLE inventory.upload_receipts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), snapshot_id uuid NOT NULL REFERENCES inventory.snapshots(id),
 source text NOT NULL CHECK(source IN ('ansible_api','dashboard_file')), received_at timestamptz NOT NULL DEFAULT now(),
 actor_user_id uuid, technical_principal_id uuid, request_id uuid NOT NULL,
 CHECK((source='ansible_api' AND technical_principal_id IS NOT NULL AND actor_user_id IS NULL)
 OR (source='dashboard_file' AND actor_user_id IS NOT NULL AND technical_principal_id IS NULL))
);
CREATE TABLE inventory.collection_sections (
 snapshot_id uuid NOT NULL REFERENCES inventory.snapshots(id), section text NOT NULL CHECK(section IN ('os','packages','services','containers')),
 status text NOT NULL CHECK(status IN ('complete','partial','failed','not_collected')), error_code text,
 PRIMARY KEY(snapshot_id,section)
);
CREATE TABLE inventory.operating_systems (
 snapshot_id uuid PRIMARY KEY REFERENCES inventory.snapshots(id), name text NOT NULL, version text NOT NULL,
 distribution text, release text, architecture text, kernel_version text, original_data jsonb NOT NULL DEFAULT '{}'
);
CREATE TABLE inventory.packages (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), snapshot_id uuid NOT NULL REFERENCES inventory.snapshots(id),
 name text NOT NULL CHECK(name<>''), version text NOT NULL CHECK(version<>''), architecture text NOT NULL,
 package_manager text NOT NULL, source_package text, source_version text, software_identity text NOT NULL,
 original_data jsonb NOT NULL DEFAULT '{}', UNIQUE(snapshot_id,name,version,architecture,package_manager)
);
CREATE TABLE inventory.services (
 snapshot_id uuid NOT NULL REFERENCES inventory.snapshots(id), name text NOT NULL, state text NOT NULL,
 enabled boolean, original_data jsonb NOT NULL DEFAULT '{}', PRIMARY KEY(snapshot_id,name)
);
CREATE TABLE inventory.containers (
 snapshot_id uuid NOT NULL REFERENCES inventory.snapshots(id), container_id text NOT NULL, name text,
 image_reference text NOT NULL, image_digest text, state text NOT NULL, original_data jsonb NOT NULL DEFAULT '{}',
 PRIMARY KEY(snapshot_id,container_id)
);
CREATE INDEX snapshots_history ON inventory.snapshots(server_id,captured_at DESC,inventory_id DESC);
CREATE INDEX snapshots_current ON inventory.snapshots(server_id,captured_at DESC,inventory_id DESC)
 WHERE collection_status='complete' AND processing_status='processed';
CREATE INDEX packages_software ON inventory.packages(name,package_manager,architecture);
CREATE VIEW inventory.current_snapshots AS SELECT DISTINCT ON(server_id) * FROM inventory.snapshots
 WHERE collection_status='complete' AND processing_status='processed' ORDER BY server_id,captured_at DESC,inventory_id DESC;
CREATE VIEW inventory.effective_sections AS
 SELECT DISTINCT ON(s.server_id,c.section) s.server_id,c.section,s.id AS snapshot_id,s.captured_at
 FROM inventory.snapshots s JOIN inventory.collection_sections c ON c.snapshot_id=s.id
 WHERE c.status='complete' AND s.processing_status='processed' AND s.collection_status<>'failed'
 ORDER BY s.server_id,c.section,s.captured_at DESC,s.inventory_id DESC;
"""
