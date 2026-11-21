"""Explicit human RBAC/ACLs, revisions and deferred last-usable-administrator invariant."""

from alembic import op

revision = "00015_authorization"
down_revision = "00014_authentication"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Reviewed security backup/restore required")


DDL = r"""
ALTER TABLE security.users ADD created_by uuid REFERENCES security.users(id);
ALTER TABLE security.roles ADD version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 ADD updated_at timestamptz NOT NULL DEFAULT clock_timestamp(), ADD created_by uuid REFERENCES security.users(id);
CREATE UNIQUE INDEX roles_name_normalized ON security.roles(casefold(normalize(btrim(name),NFKC)));
ALTER TABLE security.permissions ADD identity_type text NOT NULL DEFAULT 'legacy' CHECK(identity_type IN ('legacy','human','machine','service')),
 ADD administrative boolean NOT NULL DEFAULT true, ADD object_scope text,
 ADD reauthentication boolean NOT NULL DEFAULT false, ADD delegable boolean NOT NULL DEFAULT false;
ALTER TABLE security.user_server_access ADD id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
 ADD findings_read boolean NOT NULL DEFAULT false, ADD findings_manage boolean NOT NULL DEFAULT false,
 ADD created_at timestamptz NOT NULL DEFAULT clock_timestamp(), ADD updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 ADD version bigint NOT NULL DEFAULT 1 CHECK(version>0), ADD CHECK(NOT findings_manage OR findings_read),
 ADD CHECK((NOT findings_read AND NOT findings_manage) OR can_read);
CREATE INDEX access_server ON security.user_server_access(server_id,user_id);
CREATE INDEX role_members ON security.user_roles(role_id,user_id);
CREATE INDEX role_permissions_lookup ON security.role_permissions(permission_code,role_id);
CREATE TABLE security.server_acl_versions(server_id uuid PRIMARY KEY REFERENCES inventory.servers(id),
 version bigint NOT NULL DEFAULT 0 CHECK(version>=0), updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE security.recovery_requests(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),user_id uuid NOT NULL REFERENCES security.users(id),
 requested_by uuid NOT NULL REFERENCES security.users(id), reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 256),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '24 hours',
 redeemed_at timestamptz,revoked_at timestamptz);
ALTER TABLE security.account_tokens ADD recovery_request_id uuid REFERENCES security.recovery_requests(id);
CREATE TABLE security.administration_state(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 armed boolean NOT NULL DEFAULT false);
INSERT INTO security.administration_state(singleton) VALUES(true);
GRANT SELECT,INSERT,UPDATE ON security.server_acl_versions,security.recovery_requests TO api_security;
GRANT DELETE ON security.user_server_access TO api_security;
GRANT UPDATE(findings_read,findings_manage,version,updated_at) ON security.user_server_access TO api_security;
GRANT UPDATE(version,updated_at) ON security.roles TO api_security;
CREATE TRIGGER roles_version BEFORE UPDATE ON security.roles FOR EACH ROW EXECUTE FUNCTION system.version_guard();
GRANT SELECT ON inventory.server_group_memberships TO api_security;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('user:list','user list','human',true,NULL,false,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('user:read','user read','human',true,NULL,false,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('user:create','user create','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('user:update','user update','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('user:enable','user enable','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('user:disable','user disable','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('user:archive','user archive','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('user:session:revoke','user session revoke','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('user:role:assign','user role assign','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('user:mfa:recovery','user mfa recovery','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('role:list','role list','human',true,NULL,false,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('role:create','role create','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('role:update','role update','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('role:delete','role delete','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('role:assign:privileged','role assign privileged','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('server:read','server read','human',false,'view',false,true) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('server:create','server create','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('server:update','server update','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('server:delete','server delete','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('server:restore','server restore','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('server:acl:manage','server acl manage','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('server:reorder','server reorder','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('group:read','group read','human',false,'view',false,true) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('group:create','group create','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('group:update','group update','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('group:delete','group delete','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('group:assign','group assign','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('group:primary:assign','group primary assign','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('group:reorder','group reorder','human',true,NULL,true,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('inventory:read','inventory read','human',false,'view',false,true) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('inventory:upload:dashboard','inventory upload dashboard','human',false,'inventory_upload',false,true) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('security:overview:read','security overview read','human',false,'view',false,true) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('cve:read','cve read','human',false,'view',false,true) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('finding:read','finding read','human',false,'findings_read',false,true) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('finding:update','finding update','human',false,'findings_manage',false,true) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('deployment:status:read','deployment status read','human',false,NULL,false,true) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('permission:read','Read permission catalog','human',true,NULL,false,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable) VALUES('audit:read','Read authorized audit metadata','human',true,NULL,false,false) ON CONFLICT(code) DO UPDATE SET description=excluded.description,identity_type=excluded.identity_type,administrative=excluded.administrative,object_scope=excluded.object_scope,reauthentication=excluded.reauthentication,delegable=excluded.delegable;
UPDATE security.permissions SET identity_type='machine' WHERE code='inventory:submit';
DELETE FROM security.role_permissions WHERE role_id IN(SELECT id FROM security.roles WHERE code IN ('admin','user_admin','security_analyst','viewer'));
INSERT INTO security.role_permissions(role_id,permission_code) SELECT r.id,p.code FROM security.roles r CROSS JOIN security.permissions p WHERE r.code='admin' AND p.code=ANY(ARRAY['audit:read','cve:read','deployment:status:read','finding:read','finding:update','group:assign','group:create','group:delete','group:primary:assign','group:read','group:reorder','group:update','inventory:read','inventory:upload:dashboard','permission:read','role:assign:privileged','role:create','role:delete','role:list','role:update','security:overview:read','server:acl:manage','server:create','server:delete','server:read','server:reorder','server:restore','server:update','user:archive','user:create','user:disable','user:enable','user:list','user:mfa:recovery','user:read','user:role:assign','user:session:revoke','user:update']);
INSERT INTO security.role_permissions(role_id,permission_code) SELECT r.id,p.code FROM security.roles r CROSS JOIN security.permissions p WHERE r.code='user_admin' AND p.code=ANY(ARRAY['audit:read','permission:read','role:list','user:create','user:disable','user:enable','user:list','user:read','user:role:assign','user:session:revoke','user:update']);
INSERT INTO security.role_permissions(role_id,permission_code) SELECT r.id,p.code FROM security.roles r CROSS JOIN security.permissions p WHERE r.code='security_analyst' AND p.code=ANY(ARRAY['cve:read','deployment:status:read','finding:read','group:read','inventory:read','security:overview:read','server:read']);
INSERT INTO security.role_permissions(role_id,permission_code) SELECT r.id,p.code FROM security.roles r CROSS JOIN security.permissions p WHERE r.code='viewer' AND p.code=ANY(ARRAY['cve:read','finding:read','group:read','inventory:read','server:read']);
CREATE FUNCTION security.usable_admin_count() RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT count(*) FROM security.users u JOIN security.password_credentials c ON c.user_id=u.id
 WHERE u.status='active' AND c.revoked_at IS NULL AND EXISTS(SELECT 1 FROM security.user_roles ur
 JOIN security.roles r ON r.id=ur.role_id WHERE ur.user_id=u.id AND r.code='admin')
 AND EXISTS(SELECT 1 FROM security.mfa_methods m WHERE m.user_id=u.id AND m.runtime_version=1 AND m.verified_at IS NOT NULL AND m.revoked_at IS NULL);
$$;
REVOKE ALL ON FUNCTION security.usable_admin_count() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION security.usable_admin_count() TO api_security,cve_migrator;
CREATE FUNCTION security.check_last_admin() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE uid uuid; role uuid; n bigint; guarded boolean;
BEGIN
 IF TG_TABLE_NAME='user_roles' THEN
  role:=CASE WHEN TG_OP='DELETE' THEN OLD.role_id ELSE NEW.role_id END;
  IF TG_OP='UPDATE' THEN
   IF NOT EXISTS(SELECT 1 FROM security.roles WHERE id IN (OLD.role_id,NEW.role_id) AND code='admin') THEN RETURN NULL; END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM security.roles WHERE id=role AND code='admin') THEN RETURN NULL; END IF;
  uid:=CASE WHEN TG_OP='DELETE' THEN OLD.user_id ELSE NEW.user_id END;
 ELSIF TG_TABLE_NAME='users' THEN
  uid:=CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END;
 ELSE uid:=CASE WHEN TG_OP='DELETE' THEN OLD.user_id ELSE NEW.user_id END;
 END IF;
 IF TG_TABLE_NAME<>'user_roles' AND NOT EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id WHERE ur.user_id=uid AND r.code='admin') THEN RETURN NULL; END IF;
 PERFORM pg_advisory_xact_lock(909001);
 SELECT armed INTO guarded FROM security.administration_state WHERE singleton FOR UPDATE;
 n:=security.usable_admin_count();
 IF guarded AND n=0 THEN RAISE EXCEPTION 'usable administrator required' USING ERRCODE='23514',CONSTRAINT='usable_administrator_required'; END IF;
 IF NOT guarded AND n>0 THEN UPDATE security.administration_state SET armed=true WHERE singleton; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER last_admin_users AFTER UPDATE OF status OR DELETE ON security.users DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION security.check_last_admin();
CREATE CONSTRAINT TRIGGER last_admin_roles AFTER INSERT OR UPDATE OR DELETE ON security.user_roles DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION security.check_last_admin();
CREATE CONSTRAINT TRIGGER last_admin_credentials AFTER INSERT OR UPDATE OF revoked_at OR DELETE ON security.password_credentials DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION security.check_last_admin();
CREATE CONSTRAINT TRIGGER last_admin_mfa AFTER INSERT OR UPDATE OF verified_at,revoked_at OR DELETE ON security.mfa_methods DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION security.check_last_admin();
UPDATE security.administration_state SET armed=security.usable_admin_count()>0;
CREATE FUNCTION security.authorization_status() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('usable_administrators',security.usable_admin_count(),'invariant_armed',(SELECT armed FROM security.administration_state),
 'system_roles',(SELECT count(*) FROM security.roles WHERE is_system),'explicit_server_grants',(SELECT count(*) FROM security.user_server_access));
$$;
REVOKE ALL ON FUNCTION security.authorization_status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION security.authorization_status() TO api_security,cve_migrator,status_probe;
INSERT INTO automation.event_types(code,producer_role,source) VALUES('authorization.security','api_security','cve-api');
INSERT INTO security.audit_actions(action,writer_role) SELECT 'authorization.'||a,'api_security' FROM unnest(ARRAY[
 'user_created','user_updated','user_enabled','user_disabled','user_archived','user_locked',
 'sessions_revoked','roles_assigned','roles_revoked','role_created','role_updated','role_deleted',
 'acl_granted','acl_revoked','mfa_recovery_requested','mfa_recovery_issued','mfa_recovery_redeemed',
 'activation_issued','activation_completed','denied','last_admin_protected']) a;
"""

DDL += r"""
CREATE FUNCTION security.custom_role_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF current_user<>'postgres_owner' AND EXISTS(SELECT 1 FROM security.roles WHERE id=NEW.role_id AND NOT is_system)
 AND NOT EXISTS(SELECT 1 FROM security.permissions WHERE code=NEW.permission_code AND identity_type='human' AND delegable)
 THEN RAISE EXCEPTION 'nondelegable permission' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER custom_role_permissions BEFORE INSERT OR UPDATE ON security.role_permissions FOR EACH ROW EXECUTE FUNCTION security.custom_role_guard();
"""

DDL += "GRANT USAGE ON SCHEMA inventory TO api_security;"
