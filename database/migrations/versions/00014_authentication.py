"""Local authentication, bounded security state and preserved legacy records."""

from alembic import op

revision = "00014_authentication"
down_revision = "00013_automation_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Reviewed backup/restore required for security records")


DDL = r"""
ALTER TABLE security.users ADD mfa_required boolean NOT NULL DEFAULT false;
ALTER TABLE security.audit_log ADD auth_runtime boolean NOT NULL DEFAULT false;
ALTER TABLE security.login_events ADD auth_runtime boolean NOT NULL DEFAULT false;
ALTER TABLE security.user_events ADD auth_runtime boolean NOT NULL DEFAULT false;
ALTER TABLE security.password_credentials ADD credential_version bigint NOT NULL DEFAULT 1 CHECK(credential_version>0),
 ADD last_verified_at timestamptz, ADD revoked_at timestamptz;
ALTER TABLE security.sessions ADD runtime_version integer NOT NULL DEFAULT 0 CHECK(runtime_version IN (0,1)),
 ADD auth_state text NOT NULL DEFAULT 'unauthenticated' CHECK(auth_state IN ('unauthenticated','password_verified','mfa_setup_required','mfa_pending','mfa_recovery','authenticated','reauthentication_required')),
 ADD credential_version bigint NOT NULL DEFAULT 1,
 ADD reauthenticated_at timestamptz, ADD reauthentication_consumed_at timestamptz,
 ADD correlation_id uuid,
 ADD CHECK(runtime_version=0 OR correlation_id IS NOT NULL);
CREATE INDEX sessions_runtime_expiry ON security.sessions(idle_expires_at,id) WHERE runtime_version=1 AND revoked_at IS NULL;
ALTER TABLE security.mfa_methods ADD runtime_version integer NOT NULL DEFAULT 0 CHECK(runtime_version IN (0,1)), ADD enrollment_session_id uuid REFERENCES security.sessions(id) ON DELETE SET NULL,
 ADD enrollment_expires_at timestamptz;
CREATE UNIQUE INDEX mfa_runtime_current ON security.mfa_methods(user_id) WHERE runtime_version=1 AND revoked_at IS NULL;
ALTER TABLE security.recovery_codes ADD revoked_at timestamptz;
CREATE TABLE security.csrf_contexts (
 id uuid PRIMARY KEY, verifier bytea NOT NULL CHECK(octet_length(verifier)=32),
 csrf_verifier bytea NOT NULL CHECK(octet_length(csrf_verifier)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL
);
CREATE INDEX csrf_expiry ON security.csrf_contexts(expires_at);
CREATE TABLE security.auth_rate_limits (
 key_hash bytea PRIMARY KEY CHECK(octet_length(key_hash)=32), hits integer NOT NULL CHECK(hits>0),
 expires_at timestamptz NOT NULL
);
CREATE INDEX auth_limits_expiry ON security.auth_rate_limits(expires_at);
CREATE FUNCTION security.auth_rate(p_key bytea,p_limit integer,p_seconds integer)
 RETURNS TABLE(allowed boolean,first_denial boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n integer; ts timestamptz:=clock_timestamp();
BEGIN
 IF session_user<>'api_security' OR octet_length(p_key)<>32 OR p_limit NOT BETWEEN 1 AND 1000 OR p_seconds NOT BETWEEN 1 AND 3600
 THEN RAISE EXCEPTION 'invalid rate context' USING ERRCODE='42501'; END IF;
 -- Global admission is checked before identity/IP keys. Bound abandoned state too.
 DELETE FROM security.auth_rate_limits WHERE key_hash IN
 (SELECT key_hash FROM security.auth_rate_limits WHERE expires_at<ts LIMIT 100);
 IF NOT EXISTS(SELECT 1 FROM security.auth_rate_limits WHERE key_hash=p_key)
 AND (SELECT count(*) FROM security.auth_rate_limits)>=10000 THEN RETURN QUERY SELECT false,false; RETURN; END IF;
 INSERT INTO security.auth_rate_limits(key_hash,hits,expires_at) VALUES(p_key,1,ts+make_interval(secs=>p_seconds))
 ON CONFLICT(key_hash) DO UPDATE SET hits=CASE WHEN auth_rate_limits.expires_at<=ts THEN 1 ELSE least(auth_rate_limits.hits+1,1000000) END,
 expires_at=CASE WHEN auth_rate_limits.expires_at<=ts THEN ts+make_interval(secs=>p_seconds) ELSE auth_rate_limits.expires_at END
 RETURNING hits INTO n;
 RETURN QUERY SELECT n<=p_limit,n=p_limit+1;
END $$;
REVOKE ALL ON FUNCTION security.auth_rate(bytea,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION security.auth_rate(bytea,integer,integer) TO api_security;
GRANT SELECT,INSERT,UPDATE,DELETE ON security.csrf_contexts TO api_security;
GRANT UPDATE(mfa_required) ON security.users TO api_security;
GRANT UPDATE(credential_version,last_verified_at,revoked_at) ON security.password_credentials TO api_security;
GRANT UPDATE(auth_state,csrf_verifier,last_seen_at,idle_expires_at,reauthenticated_at,reauthentication_consumed_at) ON security.sessions TO api_security;
GRANT UPDATE(enrollment_session_id,enrollment_expires_at,ciphertext,key_id) ON security.mfa_methods TO api_security;
GRANT UPDATE(revoked_at) ON security.recovery_codes TO api_security;
INSERT INTO automation.event_types(code,producer_role,source) VALUES ('auth.security','api_security','cve-api');
INSERT INTO security.audit_actions(action,writer_role) SELECT 'auth.'||a,'api_security' FROM unnest(ARRAY[
 'login_success','login_failure','mfa_required','mfa_failure','rate_limited','mfa_enrollment_started',
 'mfa_enabled','session_revoked','reauthenticated','password_changed','recovery_used',
 'password_reset_prepared','password_reset_completed']) a;
CREATE FUNCTION security.bootstrap_admin(p_name text,p_email text,p_hash text) RETURNS uuid
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE uid uuid;
BEGIN
 IF session_user<>'cve_migrator' THEN RAISE EXCEPTION 'operator context required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(807001);
 IF EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id WHERE r.code='admin')
 THEN RAISE EXCEPTION 'bootstrap already completed' USING ERRCODE='55000'; END IF;
 IF length(p_name) NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'invalid username'; END IF;
 INSERT INTO security.users(username,email,display_name,status,mfa_required)
 VALUES(p_name,p_email,p_name,'active',true) RETURNING id INTO uid;
 INSERT INTO security.password_credentials(user_id,password_hash) VALUES(uid,p_hash);
 INSERT INTO security.user_roles(user_id,role_id) SELECT uid,id FROM security.roles WHERE code='admin';
 INSERT INTO security.audit_log(actor_user_id,action,object_type,object_id,outcome,auth_runtime)
 VALUES(uid,'auth.bootstrap','user',uid::text,'success',true);
 RETURN uid;
END $$;
REVOKE ALL ON FUNCTION security.bootstrap_admin(text,text,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA security TO cve_migrator;
GRANT EXECUTE ON FUNCTION security.bootstrap_admin(text,text,text) TO cve_migrator;
CREATE TABLE security.auth_counters(name text PRIMARY KEY,n bigint NOT NULL DEFAULT 0 CHECK(n>=0));
INSERT INTO security.auth_counters(name) SELECT unnest(ARRAY['login_success','login_failure','mfa_failure','rate_limited','session_invalid','dependency_failure']);
GRANT SELECT,UPDATE(n) ON security.auth_counters TO api_security;
CREATE FUNCTION security.auth_metrics() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('counters',(SELECT jsonb_object_agg(name,n) FROM security.auth_counters),
 'active_sessions',(SELECT count(*) FROM security.sessions s JOIN security.users u ON u.id=s.user_id
 JOIN security.password_credentials c ON c.user_id=u.id WHERE s.runtime_version=1 AND s.revoked_at IS NULL
 AND s.auth_state='authenticated' AND s.expires_at>clock_timestamp() AND s.idle_expires_at>clock_timestamp()
 AND u.status='active' AND c.credential_version=s.credential_version AND c.revoked_at IS NULL),
 'rate_buckets',(SELECT count(*) FROM security.auth_rate_limits WHERE expires_at>clock_timestamp()));
$$;
REVOKE ALL ON FUNCTION security.auth_metrics() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION security.auth_metrics() TO api_security,status_probe;
GRANT USAGE ON SCHEMA security TO status_probe;
CREATE FUNCTION security.auth_cleanup() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n integer;
BEGIN
 IF session_user<>'api_security' THEN RAISE EXCEPTION 'invalid maintenance context' USING ERRCODE='42501'; END IF;
 DELETE FROM security.sessions WHERE id IN(SELECT id FROM security.sessions WHERE runtime_version=1
 AND least(expires_at,idle_expires_at)<clock_timestamp()-interval '30 days' LIMIT 200);
 DELETE FROM security.account_tokens WHERE id IN(SELECT id FROM security.account_tokens
 WHERE purpose='password_reset' AND expires_at<clock_timestamp()-interval '30 days' LIMIT 200);
 DELETE FROM security.csrf_contexts WHERE id IN(SELECT id FROM security.csrf_contexts WHERE expires_at<clock_timestamp() LIMIT 200);
 GET DIAGNOSTICS n=ROW_COUNT;
 DELETE FROM security.auth_rate_limits WHERE key_hash IN(SELECT key_hash FROM security.auth_rate_limits WHERE expires_at<clock_timestamp() LIMIT 200);
 UPDATE security.sessions SET revoked_at=clock_timestamp() WHERE id IN(SELECT id FROM security.sessions WHERE runtime_version=1
 AND revoked_at IS NULL AND least(expires_at,idle_expires_at)<clock_timestamp() LIMIT 200);
 RETURN n;
END $$;
REVOKE ALL ON FUNCTION security.auth_cleanup() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION security.auth_cleanup() TO api_security;
"""

DDL += r"""
CREATE FUNCTION security.auth_history_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' AND current_user='postgres_owner' AND OLD.auth_runtime
 AND OLD.occurred_at<clock_timestamp()-interval '90 days' THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'append-only authentication history' USING ERRCODE='42501';
END $$;
DROP TRIGGER audit_immutable ON security.audit_log;
DROP TRIGGER login_events_immutable ON security.login_events;
DROP TRIGGER user_events_immutable ON security.user_events;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON security.audit_log FOR EACH ROW EXECUTE FUNCTION security.auth_history_guard();
CREATE TRIGGER login_events_immutable BEFORE UPDATE OR DELETE ON security.login_events FOR EACH ROW EXECUTE FUNCTION security.auth_history_guard();
CREATE TRIGGER user_events_immutable BEFORE UPDATE OR DELETE ON security.user_events FOR EACH ROW EXECUTE FUNCTION security.auth_history_guard();
CREATE FUNCTION security.auth_purge_archived(p_receipt uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a integer; l integer; u integer;
BEGIN
 IF session_user<>'cve_migrator' OR p_receipt IS NULL THEN RAISE EXCEPTION 'operator archive receipt required' USING ERRCODE='42501'; END IF;
 DELETE FROM security.login_events WHERE id IN(SELECT id FROM security.login_events WHERE auth_runtime AND occurred_at<clock_timestamp()-interval '90 days' ORDER BY occurred_at LIMIT 500);
 GET DIAGNOSTICS l=ROW_COUNT;
 DELETE FROM security.user_events WHERE id IN(SELECT id FROM security.user_events WHERE auth_runtime AND occurred_at<clock_timestamp()-interval '90 days' ORDER BY occurred_at LIMIT 500);
 GET DIAGNOSTICS u=ROW_COUNT;
 DELETE FROM security.audit_log WHERE id IN(SELECT id FROM security.audit_log WHERE auth_runtime AND occurred_at<clock_timestamp()-interval '90 days' ORDER BY occurred_at LIMIT 500);
 GET DIAGNOSTICS a=ROW_COUNT;
 INSERT INTO security.audit_log(action,object_type,object_id,outcome,metadata,auth_runtime)
 VALUES('auth.retention_purged','archive',p_receipt::text,'success',jsonb_build_object('audit_rows',a,'login_rows',l,'user_rows',u),true);
 RETURN jsonb_build_object('audit_rows',a,'login_rows',l,'user_rows',u);
END $$;
REVOKE ALL ON FUNCTION security.auth_purge_archived(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION security.auth_purge_archived(uuid) TO cve_migrator;
"""

DDL += r"""
CREATE FUNCTION security.invalidate_runtime_sessions() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF (NEW.status IS DISTINCT FROM OLD.status AND NEW.status<>'active')
 OR NEW.auth_version<>OLD.auth_version THEN
  UPDATE security.sessions SET revoked_at=clock_timestamp() WHERE user_id=NEW.id AND runtime_version=1 AND revoked_at IS NULL;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER users_auth_invalidation AFTER UPDATE OF status,auth_version ON security.users
 FOR EACH ROW EXECUTE FUNCTION security.invalidate_runtime_sessions();
"""
