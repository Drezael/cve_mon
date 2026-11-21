"""administration — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "0002_administration"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
CREATE TABLE inventory.server_groups (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL CHECK(btrim(name)<>''),
 description text, sort_order bigint NOT NULL DEFAULT 0 CHECK(sort_order>=0),
 status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','archived')),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 UNIQUE (name)
);
CREATE UNIQUE INDEX groups_normalized_name ON inventory.server_groups(casefold(normalize(btrim(name),NFKC)));
CREATE TABLE inventory.servers (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), display_name text NOT NULL CHECK(btrim(display_name)<>''),
 inventory_hostname text NOT NULL CHECK(btrim(inventory_hostname)<>''),
 inventory_name text NOT NULL CHECK(btrim(inventory_name)<>''), description text,
 environment text, criticality text NOT NULL DEFAULT 'medium' CHECK(criticality IN ('low','medium','high','critical')),
 status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive','archived')),
 primary_group_id uuid REFERENCES inventory.server_groups(id),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 archived_at timestamptz, version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 CHECK((status='archived')=(archived_at IS NOT NULL))
);
CREATE UNIQUE INDEX servers_inventory_identity ON inventory.servers
 (casefold(normalize(btrim(inventory_name),NFKC)),casefold(normalize(btrim(inventory_hostname),NFKC)));
CREATE TABLE inventory.server_group_memberships (
 server_id uuid NOT NULL REFERENCES inventory.servers(id), group_id uuid NOT NULL REFERENCES inventory.server_groups(id),
 display_order bigint NOT NULL DEFAULT 0 CHECK(display_order>=0), created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(server_id,group_id)
);
ALTER TABLE inventory.servers ADD CONSTRAINT primary_group_is_membership FOREIGN KEY(id,primary_group_id)
 REFERENCES inventory.server_group_memberships(server_id,group_id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX memberships_group_order ON inventory.server_group_memberships(group_id,display_order,server_id);
CREATE TRIGGER servers_version BEFORE UPDATE ON inventory.servers FOR EACH ROW EXECUTE FUNCTION system.version_guard();
CREATE TRIGGER groups_version BEFORE UPDATE ON inventory.server_groups FOR EACH ROW EXECUTE FUNCTION system.version_guard();
CREATE TABLE dashboard.ungrouped_server_order (
 server_id uuid PRIMARY KEY REFERENCES inventory.servers(id), display_order bigint NOT NULL CHECK(display_order>=0)
);
CREATE TABLE dashboard.order_versions (scope text PRIMARY KEY, version bigint NOT NULL CHECK(version>0));
INSERT INTO dashboard.order_versions VALUES ('groups',1),('ungrouped',1);
CREATE VIEW dashboard.group_order AS SELECT id AS group_id,sort_order AS position,version FROM inventory.server_groups;
CREATE VIEW dashboard.server_order AS
 SELECT server_id,group_id,display_order AS position FROM inventory.server_group_memberships
 UNION ALL SELECT server_id,NULL::uuid,display_order FROM dashboard.ungrouped_server_order;
"""
