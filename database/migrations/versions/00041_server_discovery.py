"""Inventory 1.2 discovers hosts atomically and grants the uploader access to their servers."""

from alembic import op

revision = "00041_server_discovery"
down_revision = "00040_workflow_control"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError(
        "Restore the reviewed backup; preserve host identities and original inventories"
    )


DDL = r"""
INSERT INTO security.permissions(code,description,identity_type,administrative,object_scope,reauthentication,delegable)
VALUES('server:inventory:manage','Server hinzufügen und aktualisieren','human',false,NULL,false,true);
INSERT INTO security.role_permissions(role_id,permission_code)
SELECT DISTINCT role_id,'server:inventory:manage' FROM security.role_permissions
WHERE permission_code IN ('server:create','inventory:upload:dashboard') ON CONFLICT DO NOTHING;
CREATE TABLE inventory.host_identities (
 server_id uuid PRIMARY KEY REFERENCES inventory.servers(id),monitoring_id uuid NOT NULL UNIQUE,
 hostname text NOT NULL CHECK(length(hostname) BETWEEN 1 AND 128),fqdn text,
 machine_id_hash text CHECK(machine_id_hash ~ '^[a-f0-9]{64}$'),
 ssh_host_key_fingerprint text CHECK(ssh_host_key_fingerprint ~ '^SHA256:[A-Za-z0-9+/]{43}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX host_machine_identity ON inventory.host_identities(machine_id_hash) WHERE machine_id_hash IS NOT NULL;
CREATE INDEX host_ssh_identity ON inventory.host_identities(ssh_host_key_fingerprint) WHERE ssh_host_key_fingerprint IS NOT NULL;
GRANT SELECT ON inventory.host_identities TO api_security,api_ingest,inventory_processor,reporter;
INSERT INTO security.audit_actions(action,writer_role) VALUES('inventory.server_discovered','postgres_owner');
CREATE FUNCTION inventory.resolve_upload_host(p_host jsonb,p_actor uuid,p_selected uuid DEFAULT NULL,p_principal uuid DEFAULT NULL)
 RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE identity inventory.host_identities; sid uuid; mid uuid; machine text; ssh text; admin boolean;
BEGIN
 IF session_user NOT IN ('api_security','api_ingest') OR p_actor IS NULL
 OR jsonb_typeof(p_host) IS DISTINCT FROM 'object' OR octet_length(p_host::text)>2048
 OR p_host->>'monitoring_id' IS NULL OR p_host->>'hostname' !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
 OR (p_host->>'machine_id_hash' IS NOT NULL AND p_host->>'machine_id_hash' !~ '^[a-f0-9]{64}$')
 OR (p_host->>'ssh_host_key_fingerprint' IS NOT NULL AND p_host->>'ssh_host_key_fingerprint' !~ '^SHA256:[A-Za-z0-9+/]{43}$')
 THEN RAISE EXCEPTION 'invalid discovery request' USING ERRCODE='42501'; END IF;
 IF session_user='api_ingest' THEN
  IF NOT EXISTS(SELECT 1 FROM security.collector_owners WHERE principal_id=p_principal AND user_id=p_actor)
  THEN RAISE EXCEPTION 'collector owner required' USING ERRCODE='42501'; END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM security.users u JOIN security.user_roles ur ON ur.user_id=u.id
 JOIN security.role_permissions rp ON rp.role_id=ur.role_id
 WHERE u.id=p_actor AND u.status='active' AND rp.permission_code='server:inventory:manage')
 THEN RAISE EXCEPTION 'discovery permission required' USING ERRCODE='42501'; END IF;
 SELECT EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id
 WHERE ur.user_id=p_actor AND r.code='admin') INTO admin;
 mid:=(p_host->>'monitoring_id')::uuid;machine:=p_host->>'machine_id_hash';ssh:=p_host->>'ssh_host_key_fingerprint';
 IF mid='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'invalid monitoring id' USING ERRCODE='22023'; END IF;
 -- Shared discovery lock keeps cross-identifier and display-order checks atomic even on first upload.
 PERFORM pg_advisory_xact_lock(410001);
 SELECT * INTO identity FROM inventory.host_identities WHERE monitoring_id=mid;
 sid:=coalesce(identity.server_id,p_selected);
 IF identity.server_id IS NOT NULL AND p_selected IS NOT NULL AND identity.server_id<>p_selected
 THEN RAISE EXCEPTION 'host identity conflict' USING ERRCODE='23505'; END IF;
 IF sid IS NOT NULL AND NOT EXISTS(SELECT 1 FROM inventory.servers s WHERE s.id=sid AND s.status='active'
 AND (admin OR s.created_by=p_actor OR EXISTS(SELECT 1 FROM security.user_server_access a
 WHERE a.server_id=s.id AND a.user_id=p_actor AND a.can_upload)))
 THEN RAISE EXCEPTION 'server not available' USING ERRCODE='P0002'; END IF;
 IF EXISTS(SELECT 1 FROM inventory.host_identities h WHERE
 ((machine IS NOT NULL AND h.machine_id_hash=machine) OR (ssh IS NOT NULL AND h.ssh_host_key_fingerprint=ssh))
 AND h.monitoring_id<>mid)
 OR (identity.machine_id_hash IS NOT NULL AND machine IS NOT NULL AND identity.machine_id_hash<>machine)
 OR (sid IS NOT NULL AND EXISTS(SELECT 1 FROM inventory.host_identities WHERE server_id=sid AND monitoring_id<>mid))
 THEN RAISE EXCEPTION 'host identity conflict' USING ERRCODE='23505'; END IF;
 IF sid IS NULL THEN
  INSERT INTO inventory.servers(display_name,inventory_hostname,inventory_name,created_by,updated_by,display_order)
  SELECT p_host->>'hostname',p_host->>'hostname',mid::text,p_actor,p_actor,coalesce(max(display_order),-1)+1
  FROM inventory.servers RETURNING id INTO sid;
  INSERT INTO security.user_server_access(user_id,server_id,can_read,can_upload,findings_read,granted_by)
  VALUES(p_actor,sid,true,true,true,p_actor);
  INSERT INTO security.server_acl_versions(server_id) VALUES(sid) ON CONFLICT DO NOTHING;
  UPDATE dashboard.order_versions SET version=version+1 WHERE scope='servers';
  INSERT INTO security.audit_log(actor_user_id,action,object_type,object_id,outcome)
  VALUES(p_actor,'inventory.server_discovered','server',sid::text,'success');
 END IF;
 INSERT INTO inventory.host_identities(server_id,monitoring_id,hostname,fqdn,machine_id_hash,ssh_host_key_fingerprint)
 VALUES(sid,mid,p_host->>'hostname',p_host->>'fqdn',machine,ssh)
 ON CONFLICT(server_id) DO UPDATE SET hostname=excluded.hostname,fqdn=coalesce(excluded.fqdn,host_identities.fqdn),
 machine_id_hash=coalesce(excluded.machine_id_hash,host_identities.machine_id_hash),
 ssh_host_key_fingerprint=coalesce(excluded.ssh_host_key_fingerprint,host_identities.ssh_host_key_fingerprint),updated_at=clock_timestamp();
 RETURN sid;
END $$;
REVOKE ALL ON FUNCTION inventory.resolve_upload_host(jsonb,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION inventory.resolve_upload_host(jsonb,uuid,uuid,uuid) TO api_security,api_ingest;
-- Originals remain byte-identical. Only legacy formats carry the internal server UUID.
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint
 WHERE conrelid='inventory.submissions'::regclass AND contype='c' LOOP
  IF c.definition LIKE '%schema_version%1.0%1.1%' THEN
   EXECUTE format('ALTER TABLE inventory.submissions DROP CONSTRAINT %I',c.conname);
  ELSIF c.definition LIKE '%payload_json%server_id%' THEN
   EXECUTE format('ALTER TABLE inventory.submissions DROP CONSTRAINT %I',c.conname);
  END IF;
 END LOOP;
END $$;
ALTER TABLE inventory.submissions ADD CONSTRAINT submissions_schema_version_check CHECK(schema_version IN ('1.0','1.1','1.2')),
 ADD CHECK(payload_json ?& ARRAY['inventory_id','schema_version','captured_at']),
 ADD CHECK(CASE WHEN schema_version='1.2' THEN payload_json ? 'host' AND NOT payload_json ? 'server_id'
 ELSE payload_json ? 'server_id' AND payload_json->>'server_id'=server_id::text END);
ALTER TABLE inventory.snapshots DROP CONSTRAINT original_identity_matches;
ALTER TABLE inventory.snapshots ADD CONSTRAINT original_identity_matches CHECK(coalesce(
 original_json->>'inventory_id'=inventory_id::text AND CASE WHEN schema_version='1.2'
 THEN original_json->'host'->>'monitoring_id' IS NOT NULL AND NOT original_json ? 'server_id'
 ELSE original_json->>'server_id'=server_id::text END,false));
ALTER TABLE inventory.snapshots DROP CONSTRAINT snapshots_schema_version_check;
ALTER TABLE inventory.snapshots ADD CONSTRAINT snapshots_schema_version_check CHECK(schema_version IN ('1.0','1.1','1.2'));
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('inventory.accept_submission()'::regprocedure) INTO definition;
 definition:=replace(definition,' SELECT * INTO limits',
 ' IF NEW.schema_version=''1.2'' AND NOT EXISTS(SELECT 1 FROM inventory.host_identities h
 WHERE h.server_id=NEW.server_id AND h.monitoring_id=(NEW.payload_json->''host''->>''monitoring_id'')::uuid)
 THEN RAISE EXCEPTION ''host binding required'' USING ERRCODE=''23514''; END IF;
 SELECT * INTO limits');
 EXECUTE definition;
 SELECT pg_get_functiondef('inventory.require_complete_sections()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'s.schema_version=''1.1''','s.schema_version IN (''1.1'',''1.2'')');
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00040_workflow_control','00041_server_discovery');
END $$;
CREATE TABLE security.collector_owners (
 principal_id uuid PRIMARY KEY REFERENCES security.technical_principals(id),user_id uuid NOT NULL REFERENCES security.users(id)
);
GRANT SELECT,INSERT,DELETE ON security.collector_owners TO api_security;
"""

DDL += r"""
CREATE FUNCTION security.collector_actor(p_principal uuid) RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
 SET search_path=pg_catalog AS $$
 SELECT o.user_id FROM security.collector_owners o JOIN security.users u ON u.id=o.user_id
 WHERE o.principal_id=p_principal AND u.status='active' AND EXISTS(
 SELECT 1 FROM security.user_roles ur JOIN security.role_permissions rp ON rp.role_id=ur.role_id
 WHERE ur.user_id=o.user_id AND rp.permission_code='server:inventory:manage') $$;
CREATE FUNCTION security.collector_can_upload(p_principal uuid,p_server uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM inventory.servers s WHERE s.id=p_server AND s.status='active'
 AND security.collector_actor(p_principal) IS NOT NULL AND (
 s.created_by=security.collector_actor(p_principal) OR EXISTS(
 SELECT 1 FROM security.user_server_access a WHERE a.server_id=s.id
 AND a.user_id=security.collector_actor(p_principal) AND a.can_upload) OR EXISTS(
 SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id
 WHERE ur.user_id=security.collector_actor(p_principal) AND r.code='admin'))) $$;
REVOKE ALL ON FUNCTION security.collector_actor(uuid),security.collector_can_upload(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION security.collector_actor(uuid),security.collector_can_upload(uuid,uuid) TO api_ingest,api_security;
DO $$ DECLARE c record; definition text; BEGIN
 FOR c IN SELECT conname FROM pg_constraint WHERE conrelid='security.api_tokens'::regclass AND contype='c'
 AND pg_get_constraintdef(oid) LIKE '%runtime_version%server_id%' LOOP
  EXECUTE format('ALTER TABLE security.api_tokens DROP CONSTRAINT %I',c.conname);
 END LOOP;
 SELECT pg_get_functiondef('security.inventory_identity(uuid,bytea,bytea,boolean)'::regprocedure) INTO definition;
 definition:=replace(definition,'JOIN security.principal_server_access a','LEFT JOIN security.principal_server_access a');
 definition:=replace(definition,'t.scope=''inventory:submit''',
 '(t.scope=''inventory:submit'' AND a.principal_id IS NOT NULL OR t.scope=''inventory:discover'' AND t.server_id IS NULL AND security.collector_actor(p.id) IS NOT NULL)');
 EXECUTE definition;
 SELECT pg_get_functiondef('inventory.accept_submission()'::regprocedure) INTO definition;
 definition:=replace(definition,'t.scope=''inventory:submit''',
 '(t.scope=''inventory:submit'' AND t.server_id=NEW.server_id OR t.scope=''inventory:discover'' AND t.server_id IS NULL AND security.collector_can_upload(p.id,NEW.server_id))');
 definition:=replace(definition,'AND t.server_id=NEW.server_id AND t.certificate_id','AND t.certificate_id');
 EXECUTE definition;
END $$;
ALTER TABLE security.api_tokens DROP CONSTRAINT api_tokens_scope_check;
ALTER TABLE security.api_tokens ADD CONSTRAINT api_tokens_scope_check CHECK(scope IN ('inventory:submit','inventory:discover'));
ALTER TABLE security.api_tokens ADD CONSTRAINT inventory_token_binding CHECK(runtime_version=0 OR (
 certificate_id IS NOT NULL AND issued_by IS NOT NULL AND
 ((scope='inventory:submit' AND server_id IS NOT NULL) OR (scope='inventory:discover' AND server_id IS NULL))));
"""
