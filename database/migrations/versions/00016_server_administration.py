"""Server administration, primary membership invariants and isolated order contexts."""

from alembic import op

revision = "00016_server_administration"
down_revision = "00015_authorization"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
ALTER TABLE inventory.servers ALTER inventory_hostname DROP NOT NULL, ALTER inventory_name DROP NOT NULL,
 ADD exposure text NOT NULL DEFAULT 'unknown' CHECK(exposure IN ('internal','restricted','internet_exposed','unknown')),
 ADD created_by uuid REFERENCES security.users(id), ADD updated_by uuid REFERENCES security.users(id),
 ADD display_order bigint CHECK(display_order>=0),
 ADD CONSTRAINT inventory_identity_pair CHECK((inventory_hostname IS NULL)=(inventory_name IS NULL));
WITH positions AS (SELECT id,row_number() OVER(ORDER BY created_at,id)-1 AS p FROM inventory.servers)
 UPDATE inventory.servers s SET display_order=p.p,version=version+1 FROM positions p WHERE s.id=p.id;
ALTER TABLE inventory.servers ALTER display_order SET NOT NULL;
ALTER TABLE inventory.servers ADD CONSTRAINT unique_server_position UNIQUE(display_order) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE inventory.server_groups ADD created_by uuid REFERENCES security.users(id), ADD updated_by uuid REFERENCES security.users(id),
 ADD archived_at timestamptz;
UPDATE inventory.server_groups SET archived_at=clock_timestamp(),version=version+1 WHERE status='archived';
ALTER TABLE inventory.server_groups ADD CHECK((status='archived')=(archived_at IS NOT NULL));
-- Reserve historical positions too: archiving hides them; restoring explicitly appends.
CREATE INDEX server_admin_order ON inventory.servers(status,display_order,id);
CREATE INDEX server_admin_filters ON inventory.servers(status,environment,criticality,exposure);
CREATE INDEX server_name_search ON inventory.servers(lower(display_name) text_pattern_ops);
CREATE INDEX memberships_server_group ON inventory.server_group_memberships(server_id,group_id);
INSERT INTO dashboard.order_versions(scope,version) VALUES('servers',1);
INSERT INTO dashboard.order_versions(scope,version) SELECT 'group:'||id,1 FROM inventory.server_groups;
CREATE TABLE inventory.administration_requests (
 actor_id uuid NOT NULL REFERENCES security.users(id), request_id uuid NOT NULL,
 request_digest text NOT NULL CHECK(length(request_digest)=64), server_id uuid NOT NULL REFERENCES inventory.servers(id),
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(actor_id,request_id)
);
-- Do not guess a primary group or silently repair old inconsistent membership data.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM inventory.servers s WHERE
  (s.primary_group_id IS NULL AND EXISTS(SELECT 1 FROM inventory.server_group_memberships m WHERE m.server_id=s.id))
  OR EXISTS(SELECT 1 FROM inventory.server_group_memberships m JOIN inventory.server_groups g ON g.id=m.group_id WHERE m.server_id=s.id AND g.status<>'active'))
 THEN RAISE EXCEPTION 'operator review required: inconsistent legacy memberships'; END IF;
END $$;
CREATE FUNCTION inventory.administration_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(1010001);
 IF TG_TABLE_NAME='servers' AND TG_OP='INSERT' THEN
  IF NEW.display_order IS NULL THEN SELECT coalesce(max(display_order),-1)+1 INTO NEW.display_order FROM inventory.servers; END IF;
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER administration_servers BEFORE INSERT OR UPDATE OR DELETE ON inventory.servers FOR EACH ROW EXECUTE FUNCTION inventory.administration_guard();
CREATE TRIGGER administration_groups BEFORE INSERT OR UPDATE OR DELETE ON inventory.server_groups FOR EACH ROW EXECUTE FUNCTION inventory.administration_guard();
CREATE TRIGGER administration_members BEFORE INSERT OR UPDATE OR DELETE ON inventory.server_group_memberships FOR EACH ROW EXECUTE FUNCTION inventory.administration_guard();
CREATE FUNCTION inventory.check_administration() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE sid uuid; gid uuid;
BEGIN
 IF TG_TABLE_NAME='servers' THEN sid:=CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END;
 ELSIF TG_TABLE_NAME='server_group_memberships' THEN
  sid:=CASE WHEN TG_OP='DELETE' THEN OLD.server_id ELSE NEW.server_id END;
  IF TG_OP='UPDATE' AND (OLD.server_id<>NEW.server_id OR OLD.group_id<>NEW.group_id) THEN
   RAISE EXCEPTION 'immutable membership identity' USING ERRCODE='23514';
  END IF;
 ELSE gid:=CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END;
 END IF;
 IF sid IS NOT NULL AND EXISTS(SELECT 1 FROM inventory.servers s WHERE s.id=sid AND
   ((s.primary_group_id IS NULL) <> NOT EXISTS(SELECT 1 FROM inventory.server_group_memberships m WHERE m.server_id=s.id)))
 THEN RAISE EXCEPTION 'primary group required exactly when memberships exist' USING ERRCODE='23514',CONSTRAINT='primary_group_required'; END IF;
 IF EXISTS(SELECT 1 FROM inventory.server_group_memberships m JOIN inventory.server_groups g ON g.id=m.group_id
  WHERE (m.server_id=sid OR m.group_id=gid) AND g.status<>'active')
 THEN RAISE EXCEPTION 'archived group must be empty' USING ERRCODE='23514',CONSTRAINT='archived_group_empty'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER primary_memberships AFTER INSERT OR UPDATE OR DELETE ON inventory.server_group_memberships DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION inventory.check_administration();
CREATE CONSTRAINT TRIGGER primary_servers AFTER INSERT OR UPDATE OR DELETE ON inventory.servers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION inventory.check_administration();
CREATE CONSTRAINT TRIGGER empty_archived_groups AFTER INSERT OR UPDATE OR DELETE ON inventory.server_groups DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION inventory.check_administration();
GRANT UPDATE(exposure,created_by,updated_by,display_order) ON inventory.servers TO dashboard_admin;
GRANT UPDATE(created_by,updated_by,archived_at) ON inventory.server_groups TO dashboard_admin;
GRANT SELECT,INSERT ON inventory.administration_requests TO dashboard_admin;
GRANT SELECT,INSERT,UPDATE ON dashboard.order_versions TO dashboard_admin;
-- Reuse Phase-8 resolver in the trusted admin context, with no account/credential mutation.
GRANT SELECT ON security.users,security.sessions,
 security.roles,security.user_roles,security.role_permissions,security.permissions,security.user_server_access TO dashboard_admin;
GRANT SELECT(user_id,credential_version,revoked_at) ON security.password_credentials TO dashboard_admin;
GRANT SELECT(id,user_id,runtime_version,verified_at,revoked_at) ON security.mfa_methods TO dashboard_admin;
GRANT UPDATE(last_login_at) ON security.users TO dashboard_admin;
GRANT UPDATE(last_seen_at,idle_expires_at,reauthentication_consumed_at) ON security.sessions TO dashboard_admin;
CREATE POLICY admin_roles_read ON security.roles FOR SELECT TO dashboard_admin USING(true);
CREATE POLICY admin_permissions_read ON security.role_permissions FOR SELECT TO dashboard_admin USING(true);
GRANT SELECT ON security.audit_log TO dashboard_admin;
CREATE POLICY administration_audit_read ON security.audit_log FOR SELECT TO dashboard_admin USING(source_role=current_user);
INSERT INTO security.audit_actions(action,writer_role) SELECT 'administration.'||a,'dashboard_admin' FROM unnest(ARRAY[
 'server_registered','server_updated','server_archived','server_restored','group_created','group_updated',
 'group_archived','group_restored','membership_added','membership_removed','primary_group_changed',
 'groups_reordered','servers_reordered','group_servers_reordered','denied']) a;
-- Harden reserved inventory metadata at all nesting levels; no upload route is introduced.
CREATE FUNCTION inventory.has_administration_fields(value jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT CASE jsonb_typeof(value)
 WHEN 'object' THEN EXISTS(SELECT 1 FROM jsonb_each(value) e WHERE
 lower(regexp_replace(normalize(e.key,NFKC),'[^a-zA-Z0-9]','','g'))=ANY(ARRAY[
 'groups','groupid','groupids','primarygroupid','groupsortorder','displayorder','sortorder','servergroups','criticality','exposure','environment'])
 OR inventory.has_administration_fields(e.value))
 WHEN 'array' THEN EXISTS(SELECT 1 FROM jsonb_array_elements(value) e WHERE inventory.has_administration_fields(e))
 ELSE false END
$$;
GRANT EXECUTE ON FUNCTION inventory.has_administration_fields(jsonb) TO api_ingest;
ALTER TABLE inventory.snapshots ADD CONSTRAINT no_administration_metadata CHECK(NOT inventory.has_administration_fields(original_json));
"""
