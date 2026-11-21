"""Fenced inventory processing, sealed snapshots and deterministic current selection."""

from alembic import op

revision = "00019_inventory_processing"
down_revision = "00018_inventory_collect_contract"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Data-preserving rollback requires reviewed backup/restore")


DDL = r"""
INSERT INTO automation.job_types(code,handler_role,producer_roles,runtime_seconds,max_attempts)
VALUES('inventory.process_submission','inventory_processor',ARRAY['api_ingest','api_security','inventory_processor']::name[],120,3);
INSERT INTO automation.event_types(code,producer_role,source)
SELECT 'inventory.'||x,'inventory_processor','inventory-processor'
FROM unnest(ARRAY['processing_started','snapshot_created','current_changed','processing_completed','processing_failed']) x;
ALTER TABLE inventory.snapshots DROP CONSTRAINT snapshots_schema_version_check;
ALTER TABLE inventory.snapshots ADD CHECK(schema_version IN ('1.0','1.1')),
 ADD submission_id uuid UNIQUE REFERENCES inventory.submissions(id),
 ADD normalizer_version text, ADD processor_version text,
 ADD package_count integer CHECK(package_count>=0), ADD service_count integer CHECK(service_count>=0),
 ADD container_count integer CHECK(container_count>=0), ADD image_count integer CHECK(image_count>=0),
 ADD quality jsonb, ADD eligible boolean NOT NULL DEFAULT false,
 ADD CHECK(submission_id IS NULL OR (normalizer_version IS NOT NULL AND processor_version IS NOT NULL
 AND package_count IS NOT NULL AND service_count IS NOT NULL AND container_count IS NOT NULL
 AND image_count IS NOT NULL AND quality IS NOT NULL));
CREATE TABLE inventory.submission_processing (
 submission_id uuid PRIMARY KEY REFERENCES inventory.submissions(id),
 job_id uuid UNIQUE REFERENCES automation.jobs(id),
 status text NOT NULL DEFAULT 'accepted' CHECK(status IN ('accepted','processing','completed','failed','rejected_after_acceptance')),
 snapshot_id uuid REFERENCES inventory.snapshots(id), started_at timestamptz, finished_at timestamptz,
 error_code text CHECK(error_code IS NULL OR error_code ~ '^[a-z_]{1,64}$'),
 CHECK((status='completed')=(snapshot_id IS NOT NULL))
);
CREATE FUNCTION inventory.processing_binding_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.status='completed' AND NOT EXISTS(
 SELECT 1 FROM inventory.snapshots s JOIN inventory.submissions q ON q.id=NEW.submission_id
 WHERE s.id=NEW.snapshot_id AND s.submission_id IS NOT NULL AND s.processing_status='processed'
 AND s.server_id=q.server_id AND s.inventory_id=q.inventory_id AND s.original_json=q.payload_json)
 THEN RAISE EXCEPTION 'processing snapshot binding mismatch' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER processing_binding BEFORE INSERT OR UPDATE ON inventory.submission_processing FOR EACH ROW EXECUTE FUNCTION inventory.processing_binding_guard();
CREATE INDEX processing_pending ON inventory.submission_processing(status,submission_id) WHERE status IN ('accepted','processing');
CREATE TABLE inventory.kernels(snapshot_id uuid PRIMARY KEY REFERENCES inventory.snapshots(id),
 version_raw text, architecture text, hardware jsonb NOT NULL DEFAULT '{}');
CREATE TABLE inventory.images(snapshot_id uuid NOT NULL REFERENCES inventory.snapshots(id),
 image_id text NOT NULL, references_json jsonb NOT NULL, repo_digests jsonb NOT NULL,
 architecture text, created_at timestamptz, original_data jsonb NOT NULL, reference_parts jsonb NOT NULL,
 PRIMARY KEY(snapshot_id,image_id));
ALTER TABLE inventory.collection_sections DROP CONSTRAINT collection_sections_section_check;
ALTER TABLE inventory.collection_sections ADD CHECK(section IN ('os','packages','services','containers','images','docker'));
ALTER TABLE inventory.packages ADD epoch text, ADD upstream_version text, ADD release text,
 ADD normalization_status text NOT NULL DEFAULT 'unknown';
-- Source metadata is part of an installation record, not a reason to silently drop it.
ALTER TABLE inventory.packages DROP CONSTRAINT packages_snapshot_id_name_version_architecture_package_mana_key;
ALTER TABLE inventory.packages ADD record_sha256 bytea;
CREATE UNIQUE INDEX packages_legacy_identity ON inventory.packages(snapshot_id,name,version,architecture,package_manager) WHERE record_sha256 IS NULL;
CREATE UNIQUE INDEX packages_record ON inventory.packages(snapshot_id,record_sha256);
ALTER TABLE inventory.services DROP CONSTRAINT services_pkey;
ALTER TABLE inventory.services ADD record_number integer NOT NULL DEFAULT 0,
 ADD manager text, ADD PRIMARY KEY(snapshot_id,name,record_number);
ALTER TABLE inventory.containers DROP CONSTRAINT containers_pkey;
ALTER TABLE inventory.containers ADD record_number integer NOT NULL DEFAULT 0,
 ADD image_id text, ADD image_resolved boolean, ADD PRIMARY KEY(snapshot_id,container_id,record_number);
CREATE INDEX packages_version ON inventory.packages(name,package_manager,version,architecture);
CREATE INDEX containers_image ON inventory.containers(image_id);
CREATE TABLE inventory.server_current_snapshots(
 server_id uuid PRIMARY KEY REFERENCES inventory.servers(id), snapshot_id uuid NOT NULL UNIQUE,
 FOREIGN KEY(snapshot_id,server_id) REFERENCES inventory.snapshots(id,server_id));
CREATE OR REPLACE FUNCTION inventory.accept_snapshot() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.submission_id IS NULL THEN
  IF NOT EXISTS(SELECT 1 FROM inventory.servers WHERE id=NEW.server_id AND status='active' FOR SHARE)
  THEN RAISE EXCEPTION 'server not active or unknown' USING ERRCODE='23514'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM inventory.submissions s WHERE s.id=NEW.submission_id
   AND s.server_id=NEW.server_id AND s.inventory_id=NEW.inventory_id AND s.payload_raw=NEW.original_bytes
   AND s.payload_sha256=NEW.content_sha256 AND s.schema_version=NEW.schema_version
   AND s.collected_at=NEW.captured_at AND s.received_at=NEW.received_at)
  THEN RAISE EXCEPTION 'submission provenance mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION inventory.sealed_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE sid uuid; sealed boolean;
BEGIN
 IF TG_TABLE_NAME='snapshots' THEN
  IF OLD.submission_id IS NOT NULL AND OLD.processing_status='processed' THEN
   RAISE EXCEPTION 'sealed inventory' USING ERRCODE='42501'; END IF;
 ELSE
  IF TG_OP='UPDATE' AND EXISTS(SELECT 1 FROM inventory.snapshots WHERE id=OLD.snapshot_id AND submission_id IS NOT NULL AND processing_status='processed') THEN
   RAISE EXCEPTION 'sealed source inventory child' USING ERRCODE='42501'; END IF;
  sid:=CASE WHEN TG_OP='DELETE' THEN OLD.snapshot_id ELSE NEW.snapshot_id END;
  SELECT submission_id IS NOT NULL AND processing_status='processed' INTO sealed FROM inventory.snapshots WHERE id=sid;
  IF sealed THEN RAISE EXCEPTION 'sealed inventory child' USING ERRCODE='42501'; END IF;
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER sealed_snapshot BEFORE UPDATE OR DELETE ON inventory.snapshots FOR EACH ROW EXECUTE FUNCTION inventory.sealed_guard();
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['collection_sections','operating_systems','packages','services','containers','kernels','images'] LOOP
 EXECUTE format('CREATE TRIGGER sealed_child BEFORE INSERT OR UPDATE OR DELETE ON inventory.%I FOR EACH ROW EXECUTE FUNCTION inventory.sealed_guard()',t);
 END LOOP;
END $$;
CREATE OR REPLACE FUNCTION inventory.require_complete_sections() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE sid uuid; s inventory.snapshots;
BEGIN
 IF TG_TABLE_NAME='snapshots' THEN sid:=NEW.id; ELSE sid:=COALESCE(NEW.snapshot_id,OLD.snapshot_id); END IF;
 SELECT * INTO s FROM inventory.snapshots WHERE id=sid;
 IF s.submission_id IS NULL THEN
  IF s.collection_status='complete' AND s.processing_status='processed'
  AND (SELECT count(*) FROM inventory.collection_sections WHERE snapshot_id=sid AND section IN ('os','packages','services') AND status='complete')<>3
  THEN RAISE EXCEPTION 'complete processed inventory needs complete core sections' USING ERRCODE='23514'; END IF;
 ELSE
  IF s.processing_status<>'processed' OR s.processed_at IS NULL
   OR (SELECT count(*) FROM inventory.packages WHERE snapshot_id=sid)<>s.package_count
   OR (SELECT count(*) FROM inventory.services WHERE snapshot_id=sid)<>s.service_count
   OR (SELECT count(*) FROM inventory.containers WHERE snapshot_id=sid)<>s.container_count
   OR (SELECT count(*) FROM inventory.images WHERE snapshot_id=sid)<>s.image_count
   OR (SELECT count(*) FROM inventory.collection_sections WHERE snapshot_id=sid)<>(CASE WHEN s.schema_version='1.1' THEN 6 ELSE 4 END)
   OR NOT EXISTS(SELECT 1 FROM inventory.kernels WHERE snapshot_id=sid)
   OR NOT EXISTS(SELECT 1 FROM inventory.submission_processing WHERE submission_id=s.submission_id AND status='completed' AND snapshot_id=sid)
  THEN RAISE EXCEPTION 'incomplete inventory transaction' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NULL;
END $$;
CREATE FUNCTION inventory.select_current(p_snapshot uuid) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s inventory.snapshots; changed integer;
BEGIN
 IF session_user<>'inventory_processor' THEN RAISE EXCEPTION 'processor required' USING ERRCODE='42501'; END IF;
 SELECT * INTO s FROM inventory.snapshots WHERE id=p_snapshot;
 IF s.id IS NULL OR s.submission_id IS NULL OR NOT s.eligible OR s.processing_status<>'processed' OR s.collection_status<>'complete' THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock_shared(909001);
 PERFORM pg_advisory_xact_lock(hashtextextended('inventory-current:'||s.server_id::text,0));
 IF NOT EXISTS(SELECT 1 FROM inventory.servers WHERE id=s.server_id AND status='active') THEN RETURN false; END IF;
 INSERT INTO inventory.server_current_snapshots VALUES(s.server_id,s.id)
 ON CONFLICT(server_id) DO UPDATE SET snapshot_id=excluded.snapshot_id
 WHERE EXISTS(SELECT 1 FROM inventory.snapshots old WHERE old.id=server_current_snapshots.snapshot_id
 AND (s.captured_at,s.inventory_id)>(old.captured_at,old.inventory_id));
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed=1;
END $$;
GRANT EXECUTE ON FUNCTION inventory.select_current(uuid) TO inventory_processor;
CREATE FUNCTION inventory.schedule_submission(p_id uuid) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s inventory.submissions; p inventory.submission_processing; j automation.jobs;
BEGIN
 IF session_user NOT IN ('api_ingest','api_security','inventory_processor') THEN RAISE EXCEPTION 'invalid scheduler' USING ERRCODE='42501'; END IF;
 SELECT * INTO s FROM inventory.submissions WHERE id=p_id;
 IF s.id IS NULL THEN RAISE EXCEPTION 'unknown submission' USING ERRCODE='22023'; END IF;
 INSERT INTO inventory.submission_processing(submission_id) VALUES(p_id) ON CONFLICT DO NOTHING;
 SELECT * INTO p FROM inventory.submission_processing WHERE submission_id=p_id FOR UPDATE;
 IF p.job_id IS NOT NULL THEN RETURN p.job_id; END IF;
 SELECT * INTO j FROM automation.enqueue_job('inventory.process_submission',1,jsonb_build_object('submission_id',p_id),
 'submission:'||p_id::text,s.correlation_id,0,NULL,NULL,3,'inventory',false);
 UPDATE inventory.submission_processing SET job_id=j.id WHERE submission_id=p_id;
 RETURN j.id;
END $$;
CREATE FUNCTION inventory.schedule_new_submission() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN PERFORM inventory.schedule_submission(NEW.id); RETURN NEW; END $$;
CREATE TRIGGER schedule_inventory AFTER INSERT ON inventory.submissions FOR EACH ROW EXECUTE FUNCTION inventory.schedule_new_submission();
CREATE FUNCTION inventory.backfill(p_limit integer DEFAULT 100) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s record; n integer:=0;
BEGIN
 IF session_user<>'inventory_processor' OR p_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'invalid backfill' USING ERRCODE='42501'; END IF;
 FOR s IN SELECT q.id FROM inventory.submissions q LEFT JOIN inventory.submission_processing p ON p.submission_id=q.id
 WHERE p.submission_id IS NULL ORDER BY q.received_at,q.id LIMIT p_limit LOOP
 PERFORM inventory.schedule_submission(s.id); n:=n+1; END LOOP; RETURN n;
END $$;
GRANT EXECUTE ON FUNCTION inventory.backfill(integer) TO inventory_processor;
GRANT SELECT ON inventory.submissions,inventory.submission_identities TO inventory_processor;
GRANT EXECUTE ON FUNCTION inventory.has_administration_fields(jsonb) TO inventory_processor;
GRANT SELECT,UPDATE ON inventory.submission_processing TO inventory_processor;
GRANT INSERT ON inventory.snapshots TO inventory_processor;
REVOKE INSERT ON inventory.snapshots,inventory.upload_receipts FROM api_ingest;
REVOKE UPDATE,DELETE ON inventory.collection_sections,inventory.operating_systems,inventory.packages,inventory.services,inventory.containers FROM inventory_processor;
GRANT SELECT,INSERT ON inventory.kernels,inventory.images TO inventory_processor;
GRANT SELECT ON inventory.server_current_snapshots,inventory.kernels,inventory.images,inventory.submission_processing TO matcher,reporter;
CREATE VIEW inventory.processing_status AS
 SELECT p.submission_id,p.job_id,
 CASE WHEN p.status IN ('completed','rejected_after_acceptance') THEN p.status
 WHEN j.status IN ('failed','timed_out','cancelled') THEN 'failed'
 WHEN j.status='running' THEN 'processing' ELSE 'accepted' END AS status,
 p.snapshot_id,p.started_at,COALESCE(p.finished_at,j.finished_at) AS finished_at,COALESCE(p.error_code,lower(j.error_code)) AS error_code,
 j.status AS job_status,j.attempts
 FROM inventory.submission_processing p JOIN automation.jobs j ON j.id=p.job_id;
GRANT SELECT ON inventory.processing_status TO inventory_processor,reporter;
CREATE VIEW inventory.matching_snapshots AS
 SELECT s.id AS snapshot_id,s.server_id,s.inventory_id,s.captured_at,s.collection_status,s.normalizer_version,
 s.schema_version,s.quality,(c.snapshot_id=s.id) IS TRUE AS is_current
 FROM inventory.snapshots s LEFT JOIN inventory.server_current_snapshots c ON c.server_id=s.server_id
 WHERE s.submission_id IS NOT NULL AND s.processing_status='processed';
GRANT SELECT ON inventory.matching_snapshots TO matcher,inventory_processor,reporter;
CREATE FUNCTION inventory.processor_metrics() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('accepted',(SELECT count(*) FROM inventory.submissions),
 'pending',(SELECT count(*) FROM inventory.processing_status WHERE status IN ('accepted','processing')),
 'completed',(SELECT count(*) FROM inventory.processing_status WHERE status='completed'),
 'failed',(SELECT count(*) FROM inventory.processing_status WHERE status IN ('failed','rejected_after_acceptance')),
 'retries',(SELECT COALESCE(sum(greatest(attempts-1,0)),0) FROM inventory.processing_status),
 'active_workers',(SELECT count(DISTINCT lease_owner) FROM automation.jobs WHERE job_type='inventory.process_submission' AND status='running'),
 'oldest_pending_seconds',(SELECT greatest(0,extract(epoch FROM clock_timestamp()-min(s.received_at))) FROM inventory.submissions s LEFT JOIN inventory.processing_status p ON p.submission_id=s.id WHERE p.status IS NULL OR p.status IN ('accepted','processing')),
 'packages',(SELECT COALESCE(sum(package_count),0) FROM inventory.snapshots),
 'containers',(SELECT COALESCE(sum(container_count),0) FROM inventory.snapshots),
 'current_changes',(SELECT count(*) FROM automation.event_outbox WHERE event_type='inventory.current_changed'),
 'database_conflicts',(SELECT count(*) FROM automation.job_attempts a JOIN automation.jobs j ON j.id=a.job_id WHERE j.job_type='inventory.process_submission' AND a.error_code='DATABASE'),
 'duration_ms',(SELECT COALESCE(sum(duration_ms),0) FROM automation.job_attempts a JOIN automation.jobs j ON j.id=a.job_id WHERE j.job_type='inventory.process_submission'));
$$;
GRANT EXECUTE ON FUNCTION inventory.processor_metrics() TO inventory_processor,reporter,status_probe;
-- Legacy views keep their columns, but processing results obey the authoritative pointer.
CREATE OR REPLACE VIEW inventory.current_snapshots AS
 SELECT DISTINCT ON(s.server_id) s.id,s.inventory_id,s.server_id,s.schema_version,s.captured_at,s.received_at,
 s.collection_status,s.content_sha256,s.original_json,s.original_bytes,s.processing_status,s.processing_error_code,s.processed_at
 FROM inventory.snapshots s WHERE s.collection_status='complete' AND s.processing_status='processed'
 AND ((s.submission_id IS NULL AND NOT EXISTS(SELECT 1 FROM inventory.server_current_snapshots c WHERE c.server_id=s.server_id))
 OR EXISTS(SELECT 1 FROM inventory.server_current_snapshots c WHERE c.snapshot_id=s.id))
 ORDER BY s.server_id,s.captured_at DESC,s.inventory_id DESC;
CREATE FUNCTION inventory.record_job_failure() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p inventory.submission_processing; s inventory.submissions; event_id uuid; payload jsonb; fingerprint bytea;
BEGIN
 IF NEW.job_type<>'inventory.process_submission' OR NEW.status NOT IN ('failed','timed_out','cancelled')
 OR OLD.status=NEW.status THEN RETURN NEW; END IF;
 SELECT * INTO p FROM inventory.submission_processing WHERE job_id=NEW.id;
 IF p.submission_id IS NULL OR p.status IN ('completed','rejected_after_acceptance') THEN RETURN NEW; END IF;
 SELECT * INTO s FROM inventory.submissions WHERE id=p.submission_id;
 -- The owner writes a fixed, metadata-only system event, including operator cancellation.
 payload:=jsonb_build_object('submission_id',s.id,'server_id',s.server_id,'snapshot_id',NULL,
 'normalizer_version','inventory-1','captured_at',s.collected_at,'collection_status',s.payload_json->>'collection_status',
 'is_current',false,'error_code',lower(COALESCE(NEW.error_code,'processing_failed')));
 fingerprint:=sha256(convert_to(jsonb_build_object('type','inventory.processing_failed','version',1,'source','inventory-processor',
 'aggregate_type','inventory','aggregate_id',s.id::text,'aggregate_version',1,'payload',payload)::text,'UTF8'));
 INSERT INTO automation.event_outbox(event_type,source,aggregate_type,aggregate_id,aggregate_version,payload,
 schema_version,idempotency_key,correlation_id,runtime_version,request_fingerprint)
 VALUES('inventory.processing_failed','inventory-processor','inventory',s.id::text,1,payload,1,
 'job-failure:'||NEW.id::text,s.correlation_id,1,fingerprint) RETURNING id INTO event_id;
 INSERT INTO automation.event_deliveries(event_id,destination,runtime_version,ordered,max_attempts)
 SELECT event_id,r.destination,1,t.requires_order,d.max_attempts FROM automation.event_routes r
 JOIN automation.event_types t ON t.code=r.event_type JOIN automation.delivery_targets d ON d.id=r.destination
 WHERE r.event_type='inventory.processing_failed' AND d.enabled;
 INSERT INTO security.audit_log(action,object_type,object_id,request_id,outcome,metadata,source_role)
 VALUES('inventory.processing_failed','inventory_submission',s.id::text,s.correlation_id,'denied',payload,'inventory_processor');

 RETURN NEW;
END $$;
INSERT INTO security.audit_actions SELECT 'inventory.'||x,'inventory_processor' FROM unnest(ARRAY['processing_started','snapshot_created','current_changed','processing_completed','processing_failed']) x;
CREATE TRIGGER inventory_job_failure AFTER UPDATE OF status ON automation.jobs FOR EACH ROW EXECUTE FUNCTION inventory.record_job_failure();

CREATE OR REPLACE FUNCTION security.inventory_metrics() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 WITH pending AS (SELECT s.received_at,s.payload_size FROM inventory.submissions s
 LEFT JOIN inventory.processing_status p ON p.submission_id=s.id WHERE p.status IS NULL OR p.status IN ('accepted','processing'))
 SELECT jsonb_build_object('counters',(SELECT jsonb_object_agg(code,n) FROM security.inventory_counters),
 'pending_count',(SELECT count(*) FROM pending),'pending_bytes',(SELECT COALESCE(sum(payload_size),0) FROM pending),
 'oldest_pending_seconds',(SELECT greatest(0,extract(epoch FROM clock_timestamp()-min(received_at))) FROM pending));
$$;

"""
