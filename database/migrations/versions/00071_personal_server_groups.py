"""Replace shared groups and primary membership with account-owned server organization."""

from alembic import op

revision = "00071_personal_server_groups"
down_revision = "00070_default_user_role"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve personal server groups")


DDL = r"""
DROP TRIGGER primary_memberships ON inventory.server_group_memberships;
DROP TRIGGER primary_servers ON inventory.servers;
DROP TRIGGER empty_archived_groups ON inventory.server_groups;
DROP FUNCTION inventory.check_administration();
ALTER TABLE inventory.servers DROP CONSTRAINT primary_group_is_membership;
UPDATE inventory.servers SET primary_group_id=NULL,version=version+1 WHERE primary_group_id IS NOT NULL;
ALTER TABLE inventory.servers ADD CONSTRAINT primary_group_retired CHECK(primary_group_id IS NULL);
ALTER TABLE inventory.server_groups DROP CONSTRAINT unique_group_position;
ALTER TABLE inventory.server_group_memberships DROP CONSTRAINT unique_member_position;
DELETE FROM dashboard.order_versions WHERE scope='groups' OR scope LIKE 'group:%';
ALTER TABLE inventory.server_groups ADD owner_id uuid REFERENCES security.users(id) ON DELETE CASCADE;
UPDATE inventory.server_groups SET owner_id=coalesce(created_by,(SELECT u.id FROM security.users u
 JOIN security.user_roles ur ON ur.user_id=u.id JOIN security.roles r ON r.id=ur.role_id
 WHERE r.code='admin' ORDER BY u.created_at,u.id LIMIT 1)),version=version+1;
ALTER TABLE inventory.server_groups ALTER owner_id SET NOT NULL;
ALTER TABLE inventory.server_groups DROP CONSTRAINT server_groups_name_key;
DROP INDEX inventory.groups_normalized_name;
CREATE UNIQUE INDEX groups_owner_name ON inventory.server_groups(owner_id,casefold(normalize(btrim(name),NFKC)));
ALTER TABLE inventory.server_group_memberships DROP CONSTRAINT server_group_memberships_group_id_fkey;
ALTER TABLE inventory.server_group_memberships ADD FOREIGN KEY(group_id) REFERENCES inventory.server_groups(id) ON DELETE CASCADE;
ALTER TABLE inventory.server_group_memberships DROP CONSTRAINT server_group_memberships_server_id_fkey;
ALTER TABLE inventory.server_group_memberships ADD FOREIGN KEY(server_id) REFERENCES inventory.servers(id) ON DELETE CASCADE;
CREATE TABLE inventory.personal_group_revisions(
 owner_id uuid PRIMARY KEY REFERENCES security.users(id) ON DELETE CASCADE,
 version bigint NOT NULL DEFAULT 0 CHECK(version>=0)
);
REVOKE INSERT,UPDATE,DELETE ON inventory.server_groups,inventory.server_group_memberships FROM dashboard_admin;
-- Old column-specific grants must also be retired.
REVOKE UPDATE(name,description,status,sort_order,version,created_by,updated_by,archived_at) ON inventory.server_groups FROM dashboard_admin;
GRANT SELECT,INSERT,UPDATE,DELETE ON inventory.server_groups,inventory.server_group_memberships,inventory.personal_group_revisions TO api_security;
DELETE FROM security.role_permissions WHERE permission_code IN ('group:create','group:update','group:delete','group:assign','group:primary:assign','group:reorder');
DELETE FROM security.permissions WHERE code IN ('group:create','group:update','group:delete','group:assign','group:primary:assign','group:reorder');
INSERT INTO security.audit_actions(action,writer_role)
SELECT 'personal_groups.'||a,'api_security' FROM unnest(ARRAY['created','updated','deleted','assigned']) a;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00070_default_user_role','00071_personal_server_groups');
END $$;
"""
