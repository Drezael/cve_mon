"""Personal mail recipients and isolated optional SMTP profiles."""

from alembic import op

revision = "00054_personal_smtp"
down_revision = "00053_smtp_configuration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve personal mail settings and audit history")


DDL = r"""
ALTER TABLE automation.smtp_configs ADD COLUMN owner_id uuid REFERENCES security.users(id) ON DELETE CASCADE;
ALTER TABLE automation.smtp_configs DROP CONSTRAINT smtp_configs_version_key;
ALTER TABLE automation.smtp_configs DROP CONSTRAINT smtp_configs_configuration_check;
ALTER TABLE automation.smtp_configs ADD CHECK(jsonb_typeof(configuration)='object' AND configuration ?& ARRAY['enabled','host','port','sender','recipients'] AND configuration-ARRAY['enabled','host','port','sender','recipients','mode']='{}'::jsonb AND (owner_id IS NULL OR configuration->>'mode' IN ('system','custom')));
CREATE UNIQUE INDEX smtp_scope_version ON automation.smtp_configs(coalesce(owner_id,'00000000-0000-0000-0000-000000000000'::uuid),version);
DROP INDEX automation.smtp_single_active;
CREATE UNIQUE INDEX smtp_single_active ON automation.smtp_configs(coalesce(owner_id,'00000000-0000-0000-0000-000000000000'::uuid)) WHERE state IN ('waiting','authorized','applying');
CREATE TABLE automation.smtp_routes (owner_id uuid PRIMARY KEY REFERENCES security.users(id) ON DELETE CASCADE,listen_port integer GENERATED ALWAYS AS IDENTITY(START WITH 20000 MAXVALUE 29999 NO CYCLE) UNIQUE NOT NULL);
GRANT SELECT ON automation.smtp_routes TO dashboard_admin;
INSERT INTO security.role_permissions(role_id,permission_code) SELECT r.id,p.code FROM security.roles r CROSS JOIN security.permissions p WHERE r.code IN ('admin','user_admin','security_analyst','viewer') AND p.code IN ('notification:read','notification:preferences:update') ON CONFLICT DO NOTHING;
CREATE FUNCTION automation.smtp_permitted(p_actor uuid,p_owner uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM security.users u JOIN security.user_roles ur ON ur.user_id=u.id JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE u.id=p_actor AND u.status='active' AND rp.permission_code=CASE WHEN p_owner IS NULL THEN 'notification:smtp:manage' ELSE 'notification:preferences:update' END AND (p_owner IS NULL OR p_owner=p_actor))
$$;
REVOKE ALL ON FUNCTION automation.smtp_permitted(uuid,uuid) FROM PUBLIC;
CREATE FUNCTION automation.request_smtp_scoped(p_id uuid,p_actor uuid,p_owner uuid,p_version bigint,p_config jsonb,p_key text,p_credentials bytea) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE previous bigint; old automation.smtp_configs; q uuid; BEGIN
 IF session_user<>'api_security' OR NOT automation.smtp_permitted(p_actor,p_owner) THEN RAISE EXCEPTION 'SMTP configuration denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(7353001);
 SELECT * INTO old FROM automation.smtp_configs WHERE id=p_id;
 IF old.id IS NOT NULL THEN
  IF old.owner_id IS DISTINCT FROM p_owner OR old.requested_by<>p_actor OR old.configuration<>p_config OR old.credentials<>p_credentials THEN RAISE EXCEPTION 'request conflict' USING ERRCODE='23505'; END IF;
  RETURN old.id;
 END IF;
 SELECT coalesce(max(version),0) INTO previous FROM automation.smtp_configs WHERE owner_id IS NOT DISTINCT FROM p_owner;
 IF p_version<>previous THEN RAISE EXCEPTION 'configuration version conflict' USING ERRCODE='40001'; END IF;
 INSERT INTO automation.smtp_configs(id,owner_id,version,configuration,credentials,key_id,requested_by) VALUES(p_id,p_owner,previous+1,p_config,p_credentials,p_key,p_actor);
 IF p_owner IS NOT NULL THEN INSERT INTO automation.smtp_routes(owner_id) VALUES(p_owner) ON CONFLICT DO NOTHING; END IF;
 INSERT INTO automation.n8n_queue(kind,producer,message_type,payload,actor_id,correlation_id,deduplication_key)
 VALUES('command',session_user,'smtp.configure',jsonb_build_object('configuration_id',p_id,'version',previous+1),p_actor,p_id,'smtp.configure:'||p_id::text) RETURNING id INTO q;
 UPDATE automation.smtp_configs SET queue_id=q WHERE id=p_id;
 INSERT INTO security.audit_log(actor_user_id,action,object_type,object_id,outcome,metadata) VALUES(p_actor,'smtp.configuration.requested','smtp_configuration',p_id::text,'success',jsonb_build_object('version',previous+1,'scope',CASE WHEN p_owner IS NULL THEN 'system' ELSE 'personal' END));
 RETURN p_id;
END $$;
REVOKE ALL ON FUNCTION automation.request_smtp_scoped(uuid,uuid,uuid,bigint,jsonb,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation.request_smtp_scoped(uuid,uuid,uuid,bigint,jsonb,text,bytea) TO api_security;
CREATE OR REPLACE FUNCTION automation.request_smtp(p_id uuid,p_actor uuid,p_version bigint,p_config jsonb,p_key text,p_credentials bytea) RETURNS uuid LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT automation.request_smtp_scoped(p_id,p_actor,NULL,p_version,p_config,p_key,p_credentials)
$$;
DO $$ DECLARE d text; old_check text := 'EXISTS(SELECT 1 FROM security.users u JOIN security.user_roles ur ON ur.user_id=u.id JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE u.id=cfg.requested_by AND u.status=''active'' AND rp.permission_code=''notification:smtp:manage'')'; BEGIN
 SELECT pg_get_functiondef('automation.n8n_decide(uuid,uuid,text,text,text)'::regprocedure) INTO d;
 IF position(old_check IN d)=0 THEN RAISE EXCEPTION 'SMTP permission migration mismatch'; END IF;
 EXECUTE replace(d,old_check,'automation.smtp_permitted(cfg.requested_by,cfg.owner_id)');
 SELECT pg_get_functiondef('automation.claim_smtp()'::regprocedure) INTO d;
 d := replace(d,old_check,'automation.smtp_permitted(cfg.requested_by,cfg.owner_id)');
 EXECUTE replace(d,'ORDER BY c.version LIMIT 1','ORDER BY q.created_at,c.created_at,c.id LIMIT 1');
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00053_smtp_configuration','00054_personal_smtp');
END $$;
-- Notification workers receive only routing metadata. They never decrypt SMTP passwords.
CREATE FUNCTION automation.personal_mail(p_owner uuid) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT c.configuration FROM automation.smtp_configs c WHERE c.owner_id=p_owner AND c.state='applied' ORDER BY c.version DESC LIMIT 1
$$;
GRANT EXECUTE ON FUNCTION automation.personal_mail(uuid) TO notification;
REVOKE ALL ON FUNCTION automation.personal_mail(uuid) FROM PUBLIC;
"""
