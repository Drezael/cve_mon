"""Account language preferences and a first-start-only persistent instance default."""

from alembic import op

revision = "00069_account_locales"
down_revision = "00068_server_report_batches"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve saved account languages and the configured instance default")


DDL = r"""
CREATE TABLE security.instance_preferences(
 singleton integer PRIMARY KEY DEFAULT 1 CHECK(singleton=1),
 default_locale text NOT NULL CHECK(default_locale IN ('de','en')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 origin text NOT NULL CHECK(origin IN ('environment','administrator')),
 updated_by uuid REFERENCES security.users(id) ON DELETE SET NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE security.user_preferences(
 user_id uuid PRIMARY KEY REFERENCES security.users(id) ON DELETE CASCADE,
 locale text CHECK(locale IN ('de','en')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON security.instance_preferences,security.user_preferences FROM PUBLIC;
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable)
VALUES('instance:settings:manage','Manage instance settings','human',true,NULL,false,false);
INSERT INTO security.role_permissions(role_id,permission_code)
SELECT id,'instance:settings:manage' FROM security.roles WHERE code='admin';
INSERT INTO security.technical_principals(name,status) VALUES('localization-service','active');

CREATE FUNCTION security.bootstrap_locale(p_locale text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE selected text; BEGIN
 IF session_user<>'api_security' THEN RAISE EXCEPTION 'API startup required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(7369001);
 -- Deliberately check persisted state before even validating environment input.
 IF EXISTS(SELECT 1 FROM security.instance_preferences WHERE singleton=1) THEN RETURN; END IF;
 selected:=coalesce(nullif(btrim(p_locale),''),'en');
 IF selected NOT IN ('de','en') THEN RAISE EXCEPTION 'Initial default language must be de or en' USING ERRCODE='22023'; END IF;
 INSERT INTO security.instance_preferences(singleton,default_locale,origin) VALUES(1,selected,'environment');
 INSERT INTO security.audit_log(technical_principal_id,action,object_type,object_id,outcome,metadata)
 SELECT id,'locale.default.initialized','instance_preferences','1','success',jsonb_build_object('default_locale',selected,'version',1)
 FROM security.technical_principals WHERE name='localization-service';
END $$;

CREATE FUNCTION security.locale_actor(p_session uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor uuid; BEGIN
 IF session_user<>'api_security' THEN RAISE EXCEPTION 'Browser security identity required' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(909001);
 SELECT u.id INTO actor FROM security.sessions s JOIN security.users u ON u.id=s.user_id
 JOIN security.password_credentials c ON c.user_id=u.id
 WHERE s.id=p_session AND s.runtime_version=1 AND s.auth_state='authenticated'
 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.idle_expires_at>clock_timestamp()
 AND u.status='active' AND c.revoked_at IS NULL AND c.credential_version=s.credential_version AND u.auth_version=s.auth_version;
 IF actor IS NULL THEN RAISE EXCEPTION 'Active authenticated account required' USING ERRCODE='42501'; END IF;
 RETURN actor;
END $$;

CREATE FUNCTION security.locale_default() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('default_locale',coalesce((SELECT default_locale FROM security.instance_preferences WHERE singleton=1),'en'));
$$;

CREATE FUNCTION security.locale_personal(p_session uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor uuid; config security.user_preferences; fallback text; BEGIN
 actor:=security.locale_actor(p_session);
 SELECT * INTO config FROM security.user_preferences WHERE user_id=actor;
 SELECT default_locale INTO fallback FROM security.instance_preferences WHERE singleton=1;
 RETURN jsonb_build_object('locale',config.locale,'effective_locale',coalesce(config.locale,fallback,'en'),
 'default_locale',coalesce(fallback,'en'),'version',coalesce(config.version,0));
END $$;

CREATE FUNCTION security.locale_personal_set(p_session uuid,p_version bigint,p_locale text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor uuid; actual bigint; BEGIN
 actor:=security.locale_actor(p_session);
 IF p_locale IS NOT NULL AND p_locale NOT IN ('de','en') THEN RAISE EXCEPTION 'Unsupported language' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(actor::text,69));
 SELECT version INTO actual FROM security.user_preferences WHERE user_id=actor FOR UPDATE;
 IF coalesce(actual,0) IS DISTINCT FROM p_version THEN RAISE EXCEPTION 'Stale language preference' USING ERRCODE='40001'; END IF;
 INSERT INTO security.user_preferences(user_id,locale) VALUES(actor,p_locale)
 ON CONFLICT(user_id) DO UPDATE SET locale=excluded.locale,version=security.user_preferences.version+1,updated_at=clock_timestamp();
 INSERT INTO security.audit_log(actor_user_id,action,object_type,object_id,outcome,metadata)
 VALUES(actor,'locale.account.updated','user_preferences',actor::text,'success',jsonb_build_object('locale',p_locale,'version',coalesce(actual,0)+1));
 RETURN security.locale_personal(p_session);
END $$;

CREATE FUNCTION security.locale_instance(p_session uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor uuid; config security.instance_preferences; BEGIN
 actor:=security.locale_actor(p_session);
 IF NOT EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.role_permissions rp ON rp.role_id=ur.role_id
 WHERE ur.user_id=actor AND rp.permission_code='instance:settings:manage') THEN
 RAISE EXCEPTION 'Instance administrator required' USING ERRCODE='42501'; END IF;
 SELECT * INTO config FROM security.instance_preferences WHERE singleton=1;
 RETURN jsonb_build_object('default_locale',coalesce(config.default_locale,'en'),'version',coalesce(config.version,0),'updated_at',config.updated_at);
END $$;

CREATE FUNCTION security.locale_instance_set(p_session uuid,p_version bigint,p_locale text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor uuid; actual bigint; BEGIN
 PERFORM security.locale_instance(p_session);
 actor:=security.locale_actor(p_session);
 IF p_locale IS NULL OR p_locale NOT IN ('de','en') THEN RAISE EXCEPTION 'Unsupported language' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(7369001);
 SELECT version INTO actual FROM security.instance_preferences WHERE singleton=1 FOR UPDATE;
 IF coalesce(actual,0) IS DISTINCT FROM p_version THEN RAISE EXCEPTION 'Stale instance settings' USING ERRCODE='40001'; END IF;
 INSERT INTO security.instance_preferences(singleton,default_locale,origin,updated_by) VALUES(1,p_locale,'administrator',actor)
 ON CONFLICT(singleton) DO UPDATE SET default_locale=excluded.default_locale,origin='administrator',updated_by=actor,
 version=security.instance_preferences.version+1,updated_at=clock_timestamp();
 INSERT INTO security.audit_log(actor_user_id,action,object_type,object_id,outcome,metadata)
 VALUES(actor,'locale.default.updated','instance_preferences','1','success',jsonb_build_object('default_locale',p_locale,'version',coalesce(actual,0)+1));
 RETURN security.locale_instance(p_session);
END $$;

REVOKE ALL ON FUNCTION security.bootstrap_locale(text),security.locale_actor(uuid),security.locale_default(),security.locale_personal(uuid),security.locale_personal_set(uuid,bigint,text),security.locale_instance(uuid),security.locale_instance_set(uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION security.bootstrap_locale(text),security.locale_default(),security.locale_personal(uuid),security.locale_personal_set(uuid,bigint,text),security.locale_instance(uuid),security.locale_instance_set(uuid,bigint,text) TO api_security;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00068_server_report_batches','00069_account_locales');
END $$;
"""
