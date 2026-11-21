"""Default ordinary user role and an enforced admin-implies-user membership invariant."""

from alembic import op

revision = "00070_default_user_role"
down_revision = "00069_account_locales"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve standard roles and the administrator membership invariant")


DDL = r"""
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM security.roles WHERE code='user') THEN
  RAISE EXCEPTION 'An existing user role requires explicit conflict resolution';
 END IF;
END $$;
INSERT INTO security.roles(code,name,description,is_system)
VALUES('user','User','Standard account for own servers, findings and personal settings',true);
INSERT INTO security.role_permissions(role_id,permission_code)
SELECT r.id,p.code FROM security.roles r CROSS JOIN security.permissions p
WHERE r.code='user' AND p.code=ANY(ARRAY[
 'server:inventory:manage','server:read','group:read','inventory:read','cve:read',
 'finding:read','finding:update','notification:read','notification:preferences:update',
 'security:overview:read'
]);
INSERT INTO security.technical_principals(name,status) VALUES('role-defaults-service','active');

CREATE FUNCTION security.ensure_admin_user() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM security.roles WHERE id=NEW.role_id AND code='admin') THEN
  INSERT INTO security.user_roles(user_id,role_id,granted_by)
  SELECT NEW.user_id,id,NEW.granted_by FROM security.roles WHERE code='user'
  ON CONFLICT(user_id,role_id) DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION security.ensure_admin_user() FROM PUBLIC;
CREATE TRIGGER admin_user_grant AFTER INSERT OR UPDATE OF user_id,role_id ON security.user_roles
FOR EACH ROW EXECUTE FUNCTION security.ensure_admin_user();

WITH added AS (
 INSERT INTO security.user_roles(user_id,role_id,granted_by)
 SELECT a.user_id,u.id,a.granted_by FROM security.user_roles a
 JOIN security.roles r ON r.id=a.role_id AND r.code='admin'
 CROSS JOIN security.roles u WHERE u.code='user'
 ON CONFLICT(user_id,role_id) DO NOTHING RETURNING user_id
)
INSERT INTO security.audit_log(technical_principal_id,action,object_type,object_id,outcome,metadata)
SELECT p.id,'authorization.admin_user_role_migrated','user',a.user_id::text,'success',
 jsonb_build_object('role','user','reason','admin_requires_user')
FROM added a CROSS JOIN security.technical_principals p WHERE p.name='role-defaults-service';

CREATE FUNCTION security.check_admin_user() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE uid uuid; candidates uuid[]; BEGIN
 -- Serialize deferred checks with the existing account/role mutation protocol.
 PERFORM pg_advisory_xact_lock(909001);
 candidates:=CASE WHEN TG_OP='INSERT' THEN ARRAY[NEW.user_id]
 WHEN TG_OP='DELETE' THEN ARRAY[OLD.user_id] ELSE ARRAY[OLD.user_id,NEW.user_id] END;
 FOREACH uid IN ARRAY candidates LOOP
  IF EXISTS(SELECT 1 FROM security.user_roles a JOIN security.roles r ON r.id=a.role_id WHERE a.user_id=uid AND r.code='admin')
  AND NOT EXISTS(SELECT 1 FROM security.user_roles a JOIN security.roles r ON r.id=a.role_id WHERE a.user_id=uid AND r.code='user') THEN
   RAISE EXCEPTION 'Every administrator must also have the user role'
   USING ERRCODE='23514',CONSTRAINT='admin_requires_user';
  END IF;
 END LOOP;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION security.check_admin_user() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER admin_user_membership AFTER INSERT OR UPDATE OR DELETE ON security.user_roles
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION security.check_admin_user();
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00069_account_locales','00070_default_user_role');
END $$;
"""
