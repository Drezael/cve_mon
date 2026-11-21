"""Source-specific vulnerability imports, immutable revisions and fenced checkpoints."""

from alembic import op

revision = "00020_cve_importer"
down_revision = "00019_inventory_processing"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Data-preserving rollback requires reviewed backup/restore")


DDL = r"""
ALTER TABLE cve.sources ADD configuration_revision integer NOT NULL DEFAULT 1 CHECK(configuration_revision>0);
CREATE TABLE cve.import_runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),source_id text NOT NULL REFERENCES cve.sources(id),
 mode text NOT NULL CHECK(mode IN ('initial','incremental','reconcile')),
 context jsonb NOT NULL CHECK(system.safe_metadata(context)),
 job_id uuid UNIQUE REFERENCES automation.jobs(id), status text NOT NULL DEFAULT 'planned'
 CHECK(status IN ('planned','running','completed','partial','failed','cancelled')),
 progress jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(progress)='object' AND system.safe_metadata(progress)), started_at timestamptz,finished_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),correlation_id uuid NOT NULL,
 request_key text NOT NULL CHECK(length(request_key) BETWEEN 1 AND 128),
 read_count bigint NOT NULL DEFAULT 0,new_count bigint NOT NULL DEFAULT 0,changed_count bigint NOT NULL DEFAULT 0,
 unchanged_count bigint NOT NULL DEFAULT 0,stale_count bigint NOT NULL DEFAULT 0,error_count bigint NOT NULL DEFAULT 0,
 download_bytes bigint NOT NULL DEFAULT 0,download_ms double precision NOT NULL DEFAULT 0,
 parse_ms double precision NOT NULL DEFAULT 0,write_ms double precision NOT NULL DEFAULT 0,
 UNIQUE(source_id,request_key),UNIQUE(id,source_id)
);
CREATE TABLE cve.source_streams (
 source_id text NOT NULL REFERENCES cve.sources(id),stream text NOT NULL CHECK(stream ~ '^[A-Za-z0-9_.+ -]{1,64}$'),
 cursor jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(cursor)='object' AND system.safe_metadata(cursor)),last_complete_run uuid REFERENCES cve.import_runs(id),
 last_success_at timestamptz,PRIMARY KEY(source_id,stream)
);
CREATE TABLE cve.source_leases(source_id text PRIMARY KEY REFERENCES cve.sources(id),active_run uuid REFERENCES cve.import_runs(id));
INSERT INTO cve.source_leases(source_id) SELECT id FROM cve.sources;
CREATE TABLE cve.source_artifacts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),source_id text NOT NULL,run_id uuid NOT NULL,
 location text NOT NULL CHECK(location LIKE 'https://%' AND length(location)<=4096),
 sha256 bytea NOT NULL CHECK(octet_length(sha256)=32),bytes bigint NOT NULL CHECK(bytes>=0),
 metadata jsonb NOT NULL DEFAULT '{}',downloaded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(run_id,source_id) REFERENCES cve.import_runs(id,source_id),
 UNIQUE(id,source_id),UNIQUE(id,run_id,source_id),UNIQUE(run_id,location,sha256)
);
CREATE TABLE cve.source_records (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),source_id text NOT NULL REFERENCES cve.sources(id),
 external_id text NOT NULL CHECK(length(external_id) BETWEEN 1 AND 256),
 current_revision_id uuid,first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),last_seen_run uuid REFERENCES cve.import_runs(id),
 present boolean NOT NULL DEFAULT true,UNIQUE(source_id,external_id),UNIQUE(id,source_id)
);
CREATE FUNCTION cve.jsonb_sha256(value jsonb) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$ SELECT sha256(convert_to(value::text,'UTF8')) $$;
GRANT EXECUTE ON FUNCTION cve.jsonb_sha256(jsonb) TO importer;
CREATE TABLE cve.source_revisions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),record_id uuid NOT NULL,source_id text NOT NULL,
 original_json jsonb NOT NULL CHECK(jsonb_typeof(original_json)='object'),
 content_sha256 bytea GENERATED ALWAYS AS(cve.jsonb_sha256(original_json)) STORED,
 original_record_sha256 bytea CHECK(original_record_sha256 IS NULL OR octet_length(original_record_sha256)=32),
 source_version text NOT NULL,source_status text NOT NULL,
 status text NOT NULL CHECK(status IN ('active','rejected','withdrawn','reserved','catalog')),
 published_at timestamptz,modified_at timestamptz,imported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 run_id uuid NOT NULL,artifact_id uuid NOT NULL,
 FOREIGN KEY(record_id,source_id) REFERENCES cve.source_records(id,source_id),
 FOREIGN KEY(run_id,source_id) REFERENCES cve.import_runs(id,source_id),
 FOREIGN KEY(artifact_id,run_id,source_id) REFERENCES cve.source_artifacts(id,run_id,source_id),
 UNIQUE(record_id,content_sha256),UNIQUE(id,record_id)
);
ALTER TABLE cve.source_records ADD FOREIGN KEY(current_revision_id,id) REFERENCES cve.source_revisions(id,record_id) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE cve.source_identifiers(identifier text PRIMARY KEY CHECK(length(identifier) BETWEEN 1 AND 256),
 kind text NOT NULL CHECK(kind IN ('cve','advisory')),
 CHECK(kind<>'cve' OR identifier ~ '^CVE-[0-9]{4}-[0-9]{4,}$'));
CREATE TABLE cve.source_record_identifiers(revision_id uuid NOT NULL REFERENCES cve.source_revisions(id),
 identifier text NOT NULL REFERENCES cve.source_identifiers(identifier),PRIMARY KEY(revision_id,identifier));
CREATE TABLE cve.source_observations (
 run_id uuid NOT NULL REFERENCES cve.import_runs(id),record_id uuid NOT NULL,revision_id uuid NOT NULL,
 artifact_id uuid NOT NULL REFERENCES cve.source_artifacts(id),position text NOT NULL,
 disposition text NOT NULL CHECK(disposition IN ('new','changed','unchanged','stale')),
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(revision_id,record_id) REFERENCES cve.source_revisions(id,record_id),
 PRIMARY KEY(run_id,record_id,revision_id)
);
CREATE FUNCTION cve.check_observation_origin() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM cve.source_artifacts a JOIN cve.import_runs u ON u.id=NEW.run_id JOIN cve.source_records r ON r.id=NEW.record_id WHERE a.id=NEW.artifact_id AND a.run_id=u.id AND a.source_id=u.source_id AND r.source_id=u.source_id) THEN
  RAISE EXCEPTION 'source observation provenance mismatch' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER observation_origin BEFORE INSERT ON cve.source_observations FOR EACH ROW EXECUTE FUNCTION cve.check_observation_origin();
CREATE TABLE cve.source_presence (
 run_id uuid NOT NULL REFERENCES cve.import_runs(id),record_id uuid NOT NULL REFERENCES cve.source_records(id),
 present boolean NOT NULL,observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(run_id,record_id)
);
CREATE TABLE cve.import_errors (
 run_id uuid NOT NULL REFERENCES cve.import_runs(id),position text NOT NULL CHECK(length(position)<=512),
 code text NOT NULL CHECK(code ~ '^[a-z_]{1,64}$'),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(run_id,position,code)
);
CREATE INDEX source_records_observed ON cve.source_records(source_id,last_seen_run);
CREATE INDEX source_revisions_modified ON cve.source_revisions(source_id,modified_at,record_id);
CREATE INDEX source_revisions_runs ON cve.source_revisions(run_id,id);
CREATE INDEX import_runs_source ON cve.import_runs(source_id,created_at DESC);
CREATE INDEX identifiers_reverse ON cve.source_record_identifiers(identifier,revision_id);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['source_revisions','source_artifacts','source_identifiers','source_record_identifiers','source_observations','source_presence','import_errors'] LOOP
 EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON cve.%I FOR EACH ROW EXECUTE FUNCTION system.append_only()',t);
 END LOOP;
END $$;
INSERT INTO automation.job_types(code,handler_role,producer_roles,runtime_seconds,max_attempts)
SELECT 'cve.import.'||id,'importer',ARRAY['api_security','importer']::name[],3600,3 FROM cve.sources;
INSERT INTO automation.event_types(code,producer_role,source)
SELECT 'cve.source.'||x,'importer','cve-importer' FROM unnest(ARRAY['new','changed','withdrawn','removed','completed','partial','failed']) x;
INSERT INTO security.audit_actions SELECT 'cve.source.'||x,'importer' FROM unnest(ARRAY['completed','partial','failed']) x;
CREATE FUNCTION cve.schedule_import(p_source text,p_mode text,p_context jsonb,p_key text,p_correlation uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old cve.import_runs;current cve.import_runs;j automation.jobs;rid uuid:=gen_random_uuid();
BEGIN
 IF session_user NOT IN ('api_security','importer') OR p_source NOT IN ('cve_list','nvd','cisa_kev','ubuntu','osv')
 OR p_mode NOT IN ('initial','incremental','reconcile') OR NOT system.safe_metadata(p_context)
 OR octet_length(p_context::text)>16384 OR length(p_key) NOT BETWEEN 1 AND 128 OR p_correlation IS NULL
 THEN RAISE EXCEPTION 'invalid import request' USING ERRCODE='42501'; END IF;
 PERFORM 1 FROM cve.source_leases WHERE source_id=p_source FOR UPDATE;
 SELECT * INTO old FROM cve.import_runs WHERE source_id=p_source AND request_key=p_key;
 IF old.id IS NOT NULL THEN
 IF old.context<>p_context OR old.mode<>p_mode THEN RAISE EXCEPTION 'import request conflict' USING ERRCODE='23505'; END IF;
 RETURN old.id; END IF;
 SELECT r.* INTO current FROM cve.import_runs r JOIN cve.source_leases l ON l.active_run=r.id WHERE l.source_id=p_source;
 IF current.id IS NOT NULL AND current.status IN ('planned','running') THEN
 IF EXISTS(SELECT 1 FROM automation.jobs WHERE id=current.job_id AND status IN ('failed','timed_out','cancelled')) THEN
 UPDATE cve.import_runs SET status='failed',finished_at=clock_timestamp() WHERE id=current.id;
 ELSE RAISE EXCEPTION 'source already importing' USING ERRCODE='55000'; END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM cve.sources WHERE id=p_source AND enabled) THEN RAISE EXCEPTION 'source disabled' USING ERRCODE='55000'; END IF;
 INSERT INTO cve.import_runs(id,source_id,mode,context,request_key,correlation_id) VALUES(rid,p_source,p_mode,p_context,p_key,p_correlation);
 SELECT * INTO j FROM automation.enqueue_job('cve.import.'||p_source,1,jsonb_build_object('run_id',rid),
 rid::text,p_correlation,0,NULL,NULL,3,'cve-import',false);
 UPDATE cve.import_runs SET job_id=j.id WHERE id=rid;
 UPDATE cve.source_leases SET active_run=rid WHERE source_id=p_source;
 RETURN rid;
END $$;
GRANT USAGE ON SCHEMA cve TO api_security;
GRANT EXECUTE ON FUNCTION cve.schedule_import(text,text,jsonb,text,uuid) TO api_security,importer;
GRANT SELECT ON cve.sources TO importer;
GRANT SELECT,INSERT,UPDATE ON cve.import_runs,cve.source_streams,cve.source_leases,cve.source_records TO importer;
GRANT SELECT,INSERT ON cve.source_artifacts,cve.source_revisions,cve.source_identifiers,cve.source_record_identifiers,cve.source_observations,cve.source_presence,cve.import_errors TO importer;
-- Legacy CVE summaries belong to Phase 16; import sources never merge into them.
REVOKE INSERT,UPDATE ON cve.records,cve.revisions FROM importer;
CREATE POLICY importer_source_cursor ON system.source_sync_state TO importer USING(true) WITH CHECK(true);
CREATE VIEW cve.current_source_records AS SELECT r.*,v.source_version,v.source_status,v.status,v.modified_at,
 v.published_at,v.original_json,v.content_sha256 FROM cve.source_records r JOIN cve.source_revisions v ON v.id=r.current_revision_id;
CREATE VIEW cve.import_run_status AS SELECT r.*,
 CASE WHEN r.status IN ('completed','partial') THEN r.status WHEN j.status IN ('failed','timed_out','cancelled') THEN
 CASE WHEN j.status='cancelled' THEN 'cancelled' ELSE 'failed' END ELSE r.status END AS effective_status,
 j.status AS job_status,j.attempts,j.error_code FROM cve.import_runs r LEFT JOIN automation.jobs j ON j.id=r.job_id;
GRANT SELECT ON cve.current_source_records,cve.import_run_status,cve.source_records,cve.source_revisions,cve.source_identifiers,cve.source_record_identifiers,cve.source_artifacts,cve.source_streams,cve.source_observations,cve.import_errors TO importer,enricher,reporter;
CREATE FUNCTION cve.importer_metrics() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('sources',(SELECT jsonb_object_agg(s.id,jsonb_build_object(
 'records',(SELECT count(*) FROM cve.source_records r WHERE r.source_id=s.id),
 'revisions',(SELECT count(*) FROM cve.source_revisions v WHERE v.source_id=s.id),
 'last_success',(SELECT max(finished_at) FROM cve.import_runs r WHERE r.source_id=s.id AND status='completed'),
 'pending',(SELECT count(*) FROM cve.import_run_status r WHERE r.source_id=s.id AND effective_status IN ('planned','running')),
 'errors',(SELECT COALESCE(sum(error_count),0) FROM cve.import_runs r WHERE r.source_id=s.id),
 'download_bytes',(SELECT COALESCE(sum(download_bytes),0) FROM cve.import_runs r WHERE r.source_id=s.id),
 'download_ms',(SELECT COALESCE(sum(download_ms),0) FROM cve.import_runs r WHERE r.source_id=s.id),
 'parse_ms',(SELECT COALESCE(sum(parse_ms),0) FROM cve.import_runs r WHERE r.source_id=s.id),
 'write_ms',(SELECT COALESCE(sum(write_ms),0) FROM cve.import_runs r WHERE r.source_id=s.id),
 'new',(SELECT COALESCE(sum(new_count),0) FROM cve.import_runs r WHERE r.source_id=s.id),
 'changed',(SELECT COALESCE(sum(changed_count),0) FROM cve.import_runs r WHERE r.source_id=s.id),
 'unchanged',(SELECT COALESCE(sum(unchanged_count),0) FROM cve.import_runs r WHERE r.source_id=s.id),
 'retries',(SELECT COALESCE(sum(greatest(attempts-1,0)),0) FROM automation.jobs j WHERE j.job_type='cve.import.'||s.id),
 'oldest_pending_seconds',(SELECT greatest(0,extract(epoch FROM clock_timestamp()-min(created_at))) FROM cve.import_run_status r WHERE r.source_id=s.id AND effective_status IN ('planned','running'))
 )) FROM cve.sources s));
$$;
GRANT EXECUTE ON FUNCTION cve.importer_metrics() TO importer,reporter,status_probe;REVOKE INSERT,UPDATE ON system.source_sync_state FROM enricher;
CREATE POLICY enricher_cursor_read ON system.source_sync_state FOR SELECT TO enricher USING(true);
CREATE TABLE cve.request_limits(source_id text PRIMARY KEY REFERENCES cve.sources(id),next_at timestamptz NOT NULL);
CREATE FUNCTION cve.reserve_request(p_source text,p_delay double precision) RETURNS double precision
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE ts timestamptz:=clock_timestamp();reserved timestamptz;
BEGIN
 IF session_user<>'importer' OR p_delay NOT BETWEEN 0.1 AND 60 THEN RAISE EXCEPTION 'invalid request budget' USING ERRCODE='42501'; END IF;
 INSERT INTO cve.request_limits VALUES(p_source,ts) ON CONFLICT DO NOTHING;
 SELECT greatest(ts,next_at) INTO reserved FROM cve.request_limits WHERE source_id=p_source FOR UPDATE;
 IF reserved>ts+interval '120 seconds' THEN RAISE EXCEPTION 'request budget exhausted' USING ERRCODE='55000'; END IF;
 UPDATE cve.request_limits SET next_at=reserved+make_interval(secs=>p_delay) WHERE source_id=p_source;
 RETURN greatest(0,extract(epoch FROM reserved-ts));
END $$;
GRANT EXECUTE ON FUNCTION cve.reserve_request(text,double precision) TO importer;
CREATE FUNCTION cve.import_job_failure() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r cve.import_runs;payload jsonb;eid uuid;
BEGIN
 IF NEW.job_type NOT LIKE 'cve.import.%' OR NEW.status NOT IN ('failed','timed_out','cancelled') OR OLD.status=NEW.status THEN RETURN NEW; END IF;
 SELECT * INTO r FROM cve.import_runs WHERE job_id=NEW.id;
 IF r.id IS NULL OR r.status IN ('completed','partial') THEN RETURN NEW; END IF;
 payload:=jsonb_build_object('run_id',r.id,'source_id',r.source_id,'record_id',NULL,'revision_id',NULL,'external_id',NULL,'code',lower(COALESCE(NEW.error_code,'failed')));
 INSERT INTO automation.event_outbox(event_type,source,aggregate_type,aggregate_id,aggregate_version,payload,schema_version,idempotency_key,correlation_id,runtime_version,request_fingerprint)
 VALUES('cve.source.failed','cve-importer','import_run',r.id::text,1,payload,1,'failed:'||NEW.id::text,r.correlation_id,1,
 sha256(convert_to(jsonb_build_object('type','cve.source.failed','version',1,'source','cve-importer','aggregate_type','import_run','aggregate_id',r.id::text,'aggregate_version',1,'payload',payload)::text,'UTF8'))) RETURNING id INTO eid;
 INSERT INTO automation.event_deliveries(event_id,destination,runtime_version,ordered,max_attempts)
 SELECT eid,route.destination,1,t.requires_order,d.max_attempts FROM automation.event_routes route
 JOIN automation.event_types t ON t.code=route.event_type JOIN automation.delivery_targets d ON d.id=route.destination
 WHERE route.event_type='cve.source.failed' AND d.enabled;
 INSERT INTO security.audit_log(action,object_type,object_id,request_id,outcome,metadata)
 VALUES('cve.source.failed','cve_import',r.id::text,r.correlation_id,'denied',jsonb_build_object('code',COALESCE(NEW.error_code,'failed')));
 INSERT INTO system.source_sync_state(source_id,last_error_code) VALUES(r.source_id,COALESCE(NEW.error_code,'failed'))
 ON CONFLICT(source_id) DO UPDATE SET last_error_code=excluded.last_error_code,updated_at=clock_timestamp();
 RETURN NEW;
END $$;
CREATE TRIGGER importer_failed AFTER UPDATE OF status ON automation.jobs FOR EACH ROW EXECUTE FUNCTION cve.import_job_failure();

"""
