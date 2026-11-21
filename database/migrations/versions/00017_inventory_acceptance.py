"""Inventory submissions and bound technical credentials, without Phase-14 processing."""

from alembic import op

revision = "00017_inventory_acceptance"
down_revision = "00016_server_administration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
CREATE TABLE security.technical_certificates (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), principal_id uuid NOT NULL REFERENCES security.technical_principals(id),
 fingerprint bytea NOT NULL UNIQUE CHECK(octet_length(fingerprint)=32), certificate_pem text NOT NULL CHECK(octet_length(certificate_pem)<=8192),
 not_before timestamptz NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), issued_by uuid NOT NULL REFERENCES security.users(id),
 CHECK(expires_at>not_before), UNIQUE(id,principal_id)
);
ALTER TABLE security.api_tokens ADD server_id uuid REFERENCES inventory.servers(id),
 ADD certificate_id uuid REFERENCES security.technical_certificates(id), ADD issued_by uuid REFERENCES security.users(id),
 ADD runtime_version integer NOT NULL DEFAULT 0 CHECK(runtime_version IN (0,1)),
 ADD disabled boolean NOT NULL DEFAULT false, ADD last_used_at timestamptz;
ALTER TABLE security.api_tokens ADD CONSTRAINT token_certificate_principal FOREIGN KEY(certificate_id,principal_id)
 REFERENCES security.technical_certificates(id,principal_id);
ALTER TABLE security.api_tokens ADD CHECK(runtime_version=0 OR (server_id IS NOT NULL AND certificate_id IS NOT NULL AND issued_by IS NOT NULL));
GRANT SELECT,INSERT ON security.technical_certificates TO api_security;
GRANT UPDATE(revoked_at) ON security.technical_certificates TO api_security;
GRANT UPDATE(disabled,last_used_at) ON security.api_tokens TO api_security;
CREATE TABLE inventory.submission_identities (
 inventory_id uuid PRIMARY KEY, server_id uuid NOT NULL REFERENCES inventory.servers(id),
 canonical_sha256 bytea NOT NULL CHECK(octet_length(canonical_sha256)=32), UNIQUE(inventory_id,server_id), UNIQUE(inventory_id,server_id,canonical_sha256)
);
CREATE TABLE inventory.submissions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), inventory_id uuid NOT NULL,
 server_id uuid NOT NULL REFERENCES inventory.servers(id),
 source text NOT NULL CHECK(source IN ('ansible_api','dashboard_file')), source_identity uuid NOT NULL,
 actor_user_id uuid REFERENCES security.users(id), session_reference uuid,
 technical_principal_id uuid REFERENCES security.technical_principals(id), token_id uuid REFERENCES security.api_tokens(id),
 certificate_id uuid REFERENCES security.technical_certificates(id), certificate_fingerprint bytea,
 schema_version text NOT NULL CHECK(schema_version='1.0'), collected_at timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(), status text NOT NULL DEFAULT 'accepted' CHECK(status='accepted'),
 payload_json jsonb NOT NULL CHECK(jsonb_typeof(payload_json)='object'), payload_raw bytea NOT NULL,
 payload_sha256 bytea NOT NULL CHECK(octet_length(payload_sha256)=32),
 canonical_sha256 bytea NOT NULL CHECK(octet_length(canonical_sha256)=32),
 payload_size integer GENERATED ALWAYS AS(octet_length(payload_raw)) STORED,
 idempotency_key text NOT NULL CHECK(length(idempotency_key)>=1 AND length(idempotency_key)<=128 AND idempotency_key ~ '^[A-Za-z0-9._:-]+$'),
 correlation_id uuid NOT NULL,
 UNIQUE(source,source_identity,server_id,idempotency_key),
 FOREIGN KEY(inventory_id,server_id) REFERENCES inventory.submission_identities(inventory_id,server_id),
 FOREIGN KEY(inventory_id,server_id,canonical_sha256) REFERENCES inventory.submission_identities(inventory_id,server_id,canonical_sha256),
 CHECK(octet_length(payload_raw) BETWEEN 1 AND 10485760),
 CHECK(payload_sha256=sha256(payload_raw)), CHECK(payload_json=convert_from(payload_raw,'UTF8')::jsonb),
 CHECK(payload_json->>'server_id'=server_id::text), CHECK(payload_json->>'inventory_id'=inventory_id::text),
 CHECK(payload_json->>'schema_version'=schema_version),
 CHECK(payload_json ?& ARRAY['server_id','inventory_id','schema_version','captured_at']),
 CHECK(collected_at=(payload_json->>'captured_at')::timestamptz),
 CHECK(NOT inventory.has_administration_fields(payload_json)),
 CHECK((source='ansible_api' AND technical_principal_id IS NOT NULL AND token_id IS NOT NULL AND certificate_id IS NOT NULL
 AND octet_length(certificate_fingerprint)=32 AND source_identity=technical_principal_id AND actor_user_id IS NULL AND session_reference IS NULL)
 OR (source='dashboard_file' AND actor_user_id IS NOT NULL AND session_reference IS NOT NULL AND source_identity=actor_user_id
 AND technical_principal_id IS NULL AND token_id IS NULL AND certificate_id IS NULL AND certificate_fingerprint IS NULL))
);
CREATE INDEX submissions_server_received ON inventory.submissions(server_id,received_at DESC,id);
CREATE INDEX submissions_pending ON inventory.submissions(received_at,id) WHERE status='accepted';
CREATE INDEX submissions_identity ON inventory.submissions(source,source_identity,id);
CREATE TRIGGER submissions_immutable BEFORE UPDATE OR DELETE ON inventory.submissions FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TRIGGER submission_identity_immutable BEFORE UPDATE OR DELETE ON inventory.submission_identities FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TABLE inventory.acceptance_limits (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), max_bytes bigint NOT NULL CHECK(max_bytes>0),
 max_count integer NOT NULL CHECK(max_count>0), max_per_server integer NOT NULL CHECK(max_per_server>0)
);
INSERT INTO inventory.acceptance_limits VALUES(true,1073741824,10000,100);
CREATE TABLE inventory.acceptance_usage (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), total_bytes bigint NOT NULL DEFAULT 0 CHECK(total_bytes>=0),
 total_count bigint NOT NULL DEFAULT 0 CHECK(total_count>=0)
);
INSERT INTO inventory.acceptance_usage(singleton) VALUES(true);
CREATE FUNCTION inventory.accept_submission() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE limits inventory.acceptance_limits; used inventory.acceptance_usage;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(909001);
 IF (session_user='api_ingest' AND NEW.source<>'ansible_api') OR (session_user='api_security' AND NEW.source<>'dashboard_file')
 THEN RAISE EXCEPTION 'wrong upload context' USING ERRCODE='42501'; END IF;
 IF NEW.source='ansible_api' AND NOT EXISTS(SELECT 1 FROM security.api_tokens t JOIN security.technical_certificates c ON c.id=t.certificate_id
 JOIN security.technical_principals p ON p.id=t.principal_id WHERE t.id=NEW.token_id AND t.runtime_version=1 AND t.scope='inventory:submit'
 AND t.principal_id=NEW.technical_principal_id AND t.server_id=NEW.server_id AND t.certificate_id=NEW.certificate_id
 AND c.fingerprint=NEW.certificate_fingerprint AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp()
 AND t.revoked_at IS NULL AND NOT t.disabled AND t.expires_at>clock_timestamp() AND p.status='active')
 THEN RAISE EXCEPTION 'invalid credential provenance' USING ERRCODE='23514'; END IF;
 IF NEW.source='dashboard_file' AND NOT EXISTS(SELECT 1 FROM security.sessions s JOIN security.users u ON u.id=s.user_id
 WHERE s.id=NEW.session_reference AND s.user_id=NEW.actor_user_id AND s.auth_state='authenticated' AND s.revoked_at IS NULL
 AND s.expires_at>clock_timestamp() AND s.idle_expires_at>clock_timestamp() AND u.status='active' AND s.auth_version=u.auth_version)
 THEN RAISE EXCEPTION 'invalid user provenance' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM inventory.servers WHERE id=NEW.server_id AND status='active' FOR SHARE)
 THEN RAISE EXCEPTION 'target not active' USING ERRCODE='23514',CONSTRAINT='submission_active_server'; END IF;
 SELECT * INTO limits FROM inventory.acceptance_limits WHERE singleton;
 SELECT * INTO used FROM inventory.acceptance_usage WHERE singleton FOR UPDATE;
 IF used.total_bytes+octet_length(NEW.payload_raw)>limits.max_bytes OR used.total_count>=limits.max_count
 OR (SELECT count(*) FROM inventory.submissions WHERE server_id=NEW.server_id)>=limits.max_per_server
 THEN RAISE EXCEPTION 'acceptance capacity reached' USING ERRCODE='23514',CONSTRAINT='submission_quota'; END IF;
 UPDATE inventory.acceptance_usage SET total_bytes=total_bytes+octet_length(NEW.payload_raw),total_count=total_count+1 WHERE singleton;
 RETURN NEW;
END $$;
CREATE TRIGGER submission_limits BEFORE INSERT ON inventory.submissions FOR EACH ROW EXECUTE FUNCTION inventory.accept_submission();
GRANT SELECT,INSERT ON inventory.submission_identities TO api_ingest,api_security;
GRANT INSERT ON inventory.submissions TO api_ingest,api_security;
GRANT SELECT(id,inventory_id,server_id,source,source_identity,received_at,status,schema_version,collected_at,canonical_sha256,idempotency_key) ON inventory.submissions TO api_ingest,api_security;
GRANT EXECUTE ON FUNCTION inventory.has_administration_fields(jsonb) TO api_security;
CREATE FUNCTION security.inventory_identity(p_id uuid,p_verifier bytea,p_fingerprint bytea,p_touch boolean DEFAULT false)
 RETURNS TABLE(token_id uuid,principal_id uuid,server_id uuid,certificate_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'api_ingest' OR octet_length(p_verifier)<>32 OR octet_length(p_fingerprint)<>32
 THEN RAISE EXCEPTION 'invalid identity context' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(909001);
 RETURN QUERY SELECT t.id,t.principal_id,t.server_id,t.certificate_id FROM security.api_tokens t
 JOIN security.technical_principals p ON p.id=t.principal_id
 JOIN security.technical_certificates c ON c.id=t.certificate_id AND c.principal_id=p.id
 JOIN security.principal_server_access a ON a.principal_id=p.id AND a.server_id=t.server_id
 WHERE t.id=p_id AND t.verifier=p_verifier AND t.runtime_version=1 AND t.scope='inventory:submit'
 AND NOT t.disabled AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp() AND p.status='active'
 AND c.fingerprint=p_fingerprint AND c.revoked_at IS NULL AND c.not_before<=clock_timestamp() AND c.expires_at>clock_timestamp();
 IF FOUND AND p_touch THEN UPDATE security.api_tokens SET last_used_at=clock_timestamp() WHERE id=p_id; END IF;
END $$;
GRANT EXECUTE ON FUNCTION security.inventory_identity(uuid,bytea,bytea,boolean) TO api_ingest;
CREATE TABLE security.inventory_rate_limits (key bytea PRIMARY KEY CHECK(octet_length(key)=32), window_at timestamptz NOT NULL, n integer NOT NULL, expires_at timestamptz NOT NULL);
CREATE INDEX inventory_rate_expiry ON security.inventory_rate_limits(expires_at);
CREATE FUNCTION security.inventory_rate(p_key bytea,p_limit integer,p_seconds integer DEFAULT 60) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE bucket timestamptz; hits integer;
BEGIN
 IF session_user NOT IN ('api_ingest','api_security') OR octet_length(p_key)<>32 OR p_limit NOT BETWEEN 1 AND 10000 OR p_seconds NOT BETWEEN 1 AND 3600
 THEN RAISE EXCEPTION 'invalid rate context' USING ERRCODE='42501'; END IF;
 bucket:=to_timestamp(floor(extract(epoch FROM clock_timestamp())/p_seconds)*p_seconds);
 DELETE FROM security.inventory_rate_limits WHERE key IN(SELECT key FROM security.inventory_rate_limits WHERE expires_at<clock_timestamp() LIMIT 100);
 INSERT INTO security.inventory_rate_limits VALUES(p_key,bucket,1,bucket+make_interval(secs=>p_seconds*2))
 ON CONFLICT(key) DO UPDATE SET n=CASE WHEN inventory_rate_limits.window_at=excluded.window_at THEN least(inventory_rate_limits.n+1,p_limit+1) ELSE 1 END,
 window_at=excluded.window_at,expires_at=excluded.expires_at RETURNING n INTO hits;
 RETURN hits<=p_limit;
END $$;
GRANT EXECUTE ON FUNCTION security.inventory_rate(bytea,integer,integer) TO api_ingest,api_security;
CREATE TABLE security.inventory_counters (code text PRIMARY KEY,n bigint NOT NULL DEFAULT 0 CHECK(n>=0));
INSERT INTO security.inventory_counters(code) SELECT unnest(ARRAY['technical_accepted','dashboard_accepted','authentication_error','permission_error','schema_error','size_error','parser_error','duplicate','quota_error']);
CREATE FUNCTION security.inventory_metric(p_code text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user NOT IN ('api_ingest','api_security') THEN RAISE EXCEPTION 'invalid metric context' USING ERRCODE='42501'; END IF;
 UPDATE security.inventory_counters SET n=n+1 WHERE code=p_code;
 IF NOT FOUND THEN RAISE EXCEPTION 'unknown metric' USING ERRCODE='22023'; END IF;
END $$;
GRANT EXECUTE ON FUNCTION security.inventory_metric(text) TO api_ingest,api_security;
CREATE FUNCTION security.inventory_metrics() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('counters',(SELECT jsonb_object_agg(code,n) FROM security.inventory_counters),
 'pending_count',(SELECT count(*) FROM inventory.submissions),'pending_bytes',(SELECT total_bytes FROM inventory.acceptance_usage),
 'oldest_pending_seconds',(SELECT greatest(0,extract(epoch FROM clock_timestamp()-min(received_at))) FROM inventory.submissions));
$$;
GRANT EXECUTE ON FUNCTION security.inventory_metrics() TO api_ingest,api_security,status_probe;
INSERT INTO automation.event_types(code,producer_role,source) VALUES('inventory.dashboard_accepted','api_security','cve-api');
INSERT INTO security.audit_actions(action,writer_role) SELECT 'inventory.'||a,r FROM unnest(ARRAY[
 'accepted','rejected','client_created','client_disabled','client_enabled','certificate_registered','certificate_revoked','token_issued','token_revoked','token_disabled','token_rotated']) a
 CROSS JOIN unnest(ARRAY['api_security','api_ingest']::name[]) r ON CONFLICT DO NOTHING;
CREATE POLICY ingest_audit_read ON security.audit_log FOR SELECT TO api_ingest USING(source_role=current_user AND object_type='inventory_submission');
GRANT SELECT ON security.audit_log TO api_ingest;
"""
