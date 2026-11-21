"""User-controlled optional MFA, safe enrollment rotation and password-only administration."""

from alembic import op

revision = "00032_optional_mfa"
down_revision = "00031_hardening_list_projection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use reviewed data-preserving backup/restore")


DDL = r"""
-- MFA enrollment is a personal opt-in; roles do not require enrollment.
UPDATE security.users u SET mfa_required=false,version=version+1
 WHERE mfa_required AND NOT EXISTS(SELECT 1 FROM security.mfa_methods m
 WHERE m.user_id=u.id AND m.runtime_version=1 AND m.verified_at IS NOT NULL);
UPDATE security.sessions s SET revoked_at=clock_timestamp()
 FROM security.users u WHERE s.user_id=u.id AND s.auth_state='mfa_setup_required'
 AND NOT u.mfa_required AND s.revoked_at IS NULL;
DROP INDEX security.mfa_runtime_current;
CREATE UNIQUE INDEX mfa_runtime_current ON security.mfa_methods(user_id)
 WHERE runtime_version=1 AND revoked_at IS NULL AND verified_at IS NOT NULL;
CREATE UNIQUE INDEX mfa_runtime_pending ON security.mfa_methods(user_id)
 WHERE runtime_version=1 AND revoked_at IS NULL AND verified_at IS NULL;
INSERT INTO security.audit_actions(action,writer_role) VALUES
 ('auth.mfa_disabled','api_security'),('auth.mfa_enrollment_cancelled','api_security');
CREATE OR REPLACE FUNCTION security.bootstrap_admin(p_name text,p_email text,p_hash text) RETURNS uuid
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE uid uuid;
BEGIN
 IF session_user<>'cve_migrator' THEN RAISE EXCEPTION 'operator context required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(807001);
 IF EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id WHERE r.code='admin')
 THEN RAISE EXCEPTION 'bootstrap already completed' USING ERRCODE='55000'; END IF;
 IF length(p_name) NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'invalid username'; END IF;
 INSERT INTO security.users(username,email,display_name,status,mfa_required)
 VALUES(p_name,p_email,p_name,'active',false) RETURNING id INTO uid;
 INSERT INTO security.password_credentials(user_id,password_hash) VALUES(uid,p_hash);
 INSERT INTO security.user_roles(user_id,role_id) SELECT uid,id FROM security.roles WHERE code='admin';
 INSERT INTO security.audit_log(actor_user_id,action,object_type,object_id,outcome,auth_runtime)
 VALUES(uid,'auth.bootstrap','user',uid::text,'success',true);
 RETURN uid;
END $$;
CREATE OR REPLACE FUNCTION security.usable_admin_count() RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT count(*) FROM security.users u JOIN security.password_credentials c ON c.user_id=u.id
 WHERE u.status='active' AND c.revoked_at IS NULL AND EXISTS(SELECT 1 FROM security.user_roles ur
 JOIN security.roles r ON r.id=ur.role_id WHERE ur.user_id=u.id AND r.code='admin')
 AND (NOT u.mfa_required OR EXISTS(SELECT 1 FROM security.mfa_methods m WHERE m.user_id=u.id AND m.runtime_version=1 AND m.verified_at IS NOT NULL AND m.revoked_at IS NULL));
$$;
CREATE OR REPLACE FUNCTION findings.authorize(p_session uuid,p_server uuid,p_action text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor uuid; administrative boolean;
BEGIN
 IF session_user<>'api_security' THEN RAISE EXCEPTION 'verified browser context required' USING ERRCODE='42501'; END IF;
 SELECT s.user_id INTO actor FROM security.sessions s JOIN security.users u ON u.id=s.user_id
 JOIN security.password_credentials c ON c.user_id=u.id
 WHERE s.id=p_session AND s.runtime_version=1 AND s.auth_state='authenticated' AND s.revoked_at IS NULL
 AND s.expires_at>clock_timestamp() AND s.idle_expires_at>clock_timestamp()
 AND u.status='active' AND c.revoked_at IS NULL AND c.credential_version=s.credential_version
 AND s.auth_version=u.auth_version
 AND ((NOT u.mfa_required AND NOT EXISTS(SELECT 1 FROM security.mfa_methods m WHERE m.user_id=u.id
 AND m.runtime_version=1 AND m.verified_at IS NOT NULL AND m.revoked_at IS NULL)) OR s.mfa_verified_at IS NOT NULL);
 IF actor IS NULL OR NOT EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.role_permissions rp ON rp.role_id=ur.role_id
 WHERE ur.user_id=actor AND rp.permission_code=p_action) THEN
 RAISE EXCEPTION 'finding access denied' USING ERRCODE='42501'; END IF;
 SELECT p.administrative INTO administrative FROM security.permissions p WHERE p.code=p_action AND p.identity_type='human';
 IF administrative AND NOT EXISTS(SELECT 1 FROM security.sessions s WHERE s.id=p_session
 AND s.reauthenticated_at>clock_timestamp()-interval '5 minutes') THEN
 RAISE EXCEPTION 'fresh authentication required' USING ERRCODE='42501'; END IF;
 IF p_server IS NOT NULL AND (NOT EXISTS(SELECT 1 FROM inventory.servers WHERE id=p_server AND status='active') OR
 NOT (EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id WHERE ur.user_id=actor AND r.code='admin')
 OR EXISTS(SELECT 1 FROM security.user_server_access a WHERE a.user_id=actor AND a.server_id=p_server AND a.findings_manage)))
 THEN RAISE EXCEPTION 'finding object denied' USING ERRCODE='42501'; END IF;
 RETURN actor;
END $$;
UPDATE security.administration_state SET armed=true WHERE security.usable_admin_count()>0;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 IF strpos(definition,'00031_hardening_list_projection')=0 THEN RAISE EXCEPTION 'Unexpected sampler head'; END IF;
 EXECUTE replace(definition,'00031_hardening_list_projection','00032_optional_mfa');
END $$;
"""
