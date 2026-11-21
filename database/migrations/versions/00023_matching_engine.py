"""Revision-bound offline matcher, indexed candidates and atomic current publication."""

from alembic import op

revision = "00023_matching_engine"
down_revision = "00022_enrichment_observability"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Data-preserving rollback requires reviewed backup/restore")


DDL = r"""
-- Preserve legacy results and their Finding FKs. Runtime v17 cannot write them.
REVOKE INSERT ON matching.results FROM matcher;
ALTER TABLE matching.runs ADD job_id uuid REFERENCES automation.jobs(id),
 ADD correlation_id uuid, ADD trigger_type text;
CREATE TABLE matching.rule_versions (
 version text PRIMARY KEY, adapters jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
INSERT INTO matching.rule_versions VALUES('matching-1','{"debian":"dpkg-1","rpm":"rpm-1","semver":"semver-2"}',now());
CREATE TABLE matching.run_inputs (
 run_id uuid NOT NULL REFERENCES matching.runs(id),
 enrichment_revision_id uuid NOT NULL, identity text NOT NULL CHECK(identity ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
 FOREIGN KEY(enrichment_revision_id,identity) REFERENCES cve.enrichment_revisions(id,identity),
 PRIMARY KEY(run_id,enrichment_revision_id), UNIQUE(run_id,enrichment_revision_id,identity));
CREATE TABLE matching.candidates (
 run_id uuid NOT NULL, enrichment_revision_id uuid NOT NULL, identity text NOT NULL,
 candidate_keys jsonb NOT NULL CHECK(jsonb_typeof(candidate_keys)='array'),
 PRIMARY KEY(run_id,enrichment_revision_id),
 FOREIGN KEY(run_id,enrichment_revision_id,identity) REFERENCES matching.run_inputs(run_id,enrichment_revision_id,identity));
CREATE TABLE matching.result_revisions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), run_id uuid NOT NULL,
 server_id uuid NOT NULL, snapshot_id uuid NOT NULL, identity text NOT NULL,
 enrichment_revision_id uuid NOT NULL, rule_version text NOT NULL REFERENCES matching.rule_versions(version),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 status text NOT NULL CHECK(status IN ('affected','not_affected','potentially_affected','unknown','not_applicable')),
 reason text NOT NULL CHECK(reason ~ '^[a-z_]{1,96}$'),
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object'), created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(run_id,snapshot_id,server_id) REFERENCES matching.runs(id,snapshot_id,server_id),
 FOREIGN KEY(run_id,enrichment_revision_id,identity) REFERENCES matching.run_inputs(run_id,enrichment_revision_id,identity),
 UNIQUE(server_id,identity,fingerprint), UNIQUE(id,server_id,identity), UNIQUE(id,snapshot_id));
CREATE INDEX matching_revision_inputs ON matching.result_revisions(snapshot_id,enrichment_revision_id,rule_version);
CREATE TABLE matching.component_results (
 result_id uuid NOT NULL REFERENCES matching.result_revisions(id), position integer NOT NULL CHECK(position>=0),
 component_id text NOT NULL, context text NOT NULL, snapshot_id uuid NOT NULL,
 package_id uuid, decision jsonb NOT NULL CHECK(jsonb_typeof(decision)='object'),
 PRIMARY KEY(result_id,position), FOREIGN KEY(result_id,snapshot_id) REFERENCES matching.result_revisions(id,snapshot_id));
ALTER TABLE inventory.packages ADD UNIQUE(id,snapshot_id);
ALTER TABLE matching.component_results ADD FOREIGN KEY(package_id,snapshot_id) REFERENCES inventory.packages(id,snapshot_id);
CREATE INDEX matching_components_identity ON matching.component_results(component_id,context);
CREATE TABLE matching.result_evidence (
 result_id uuid NOT NULL REFERENCES matching.result_revisions(id), position integer NOT NULL,
 value jsonb NOT NULL, PRIMARY KEY(result_id,position));
CREATE TABLE matching.result_conflicts (
 result_id uuid NOT NULL REFERENCES matching.result_revisions(id), position integer NOT NULL,
 value jsonb NOT NULL, PRIMARY KEY(result_id,position));
CREATE TABLE matching.coverage (
 result_id uuid PRIMARY KEY REFERENCES matching.result_revisions(id), value jsonb NOT NULL);
CREATE TABLE matching.current_results (
 server_id uuid NOT NULL REFERENCES inventory.servers(id), identity text NOT NULL,
 result_id uuid NOT NULL, current_version bigint NOT NULL CHECK(current_version>0),
 PRIMARY KEY(server_id,identity),
 FOREIGN KEY(result_id,server_id,identity) REFERENCES matching.result_revisions(id,server_id,identity));
CREATE INDEX matching_current_identity ON matching.current_results(identity,server_id);
CREATE INDEX enrichment_current_matching ON cve.enrichment_identities(current_revision_id,identity);
CREATE TABLE matching.vulnerability_keys (
 enrichment_revision_id uuid NOT NULL REFERENCES cve.enrichment_revisions(id), key text NOT NULL CHECK(length(key) BETWEEN 1 AND 4096),
 PRIMARY KEY(enrichment_revision_id,key));
CREATE INDEX matching_vulnerability_lookup ON matching.vulnerability_keys(key,enrichment_revision_id);
CREATE TABLE matching.indexed_revisions (
 enrichment_revision_id uuid PRIMARY KEY REFERENCES cve.enrichment_revisions(id),
 rule_version text NOT NULL REFERENCES matching.rule_versions(version), unmapped_count integer NOT NULL CHECK(unmapped_count>=0));
CREATE TABLE matching.inventory_keys (
 snapshot_id uuid NOT NULL REFERENCES inventory.snapshots(id), key text NOT NULL CHECK(length(key) BETWEEN 1 AND 4096),
 PRIMARY KEY(snapshot_id,key));
CREATE INDEX matching_inventory_lookup ON matching.inventory_keys(key,snapshot_id);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['run_inputs','candidates','result_revisions','component_results','result_evidence','result_conflicts','coverage','rule_versions','vulnerability_keys','indexed_revisions','inventory_keys'] LOOP
 EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON matching.%I FOR EACH ROW EXECUTE FUNCTION system.append_only()',t);
 EXECUTE format('GRANT SELECT ON matching.%I TO matcher,reporter,findings_writer',t);
 IF t<>'rule_versions' THEN EXECUTE format('GRANT INSERT ON matching.%I TO matcher',t); END IF;
 END LOOP;
END $$;
CREATE FUNCTION matching.sealed_child() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE eid uuid; src uuid;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM matching.result_revisions r WHERE r.id=NEW.result_id
 AND r.xmin::text=pg_current_xact_id()::text) THEN
 RAISE EXCEPTION 'sealed matching child' USING ERRCODE='42501'; END IF;
 IF TG_TABLE_NAME='result_evidence' THEN
  src:=(NEW.value->'provenance'->>'source_revision_id')::uuid;
  SELECT enrichment_revision_id INTO eid FROM matching.result_revisions WHERE id=NEW.result_id;
  IF src IS NULL OR NOT EXISTS(SELECT 1 FROM cve.enrichment_inputs WHERE enrichment_revision_id=eid AND source_revision_id=src)
  THEN RAISE EXCEPTION 'evidence provenance mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['component_results','result_evidence','result_conflicts','coverage'] LOOP
 EXECUTE format('CREATE TRIGGER sealed_child BEFORE INSERT ON matching.%I FOR EACH ROW EXECUTE FUNCTION matching.sealed_child()',t);
 END LOOP;
END $$;
GRANT SELECT ON matching.current_results TO matcher,reporter,findings_writer;
-- The only publication path locks both authoritative pointers before checking them.
CREATE FUNCTION matching.publish(p_result uuid,p_correlation uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r matching.result_revisions; old uuid; counter bigint; changes text[]; category text;
BEGIN
 IF session_user<>'matcher' THEN RAISE EXCEPTION 'matcher required' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM matching.result_revisions WHERE id=p_result;
 IF r.id IS NULL THEN RAISE EXCEPTION 'unknown result' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('matching-current:'||r.server_id::text||':'||r.identity,0));
 IF NOT EXISTS(SELECT 1 FROM inventory.servers WHERE id=r.server_id AND status='active' FOR SHARE)
 OR NOT EXISTS(SELECT 1 FROM inventory.server_current_snapshots WHERE server_id=r.server_id AND snapshot_id=r.snapshot_id FOR SHARE)
 OR NOT EXISTS(SELECT 1 FROM cve.enrichment_identities WHERE identity=r.identity AND current_revision_id=r.enrichment_revision_id FOR SHARE)
 THEN RETURN false; END IF;
 SELECT result_id,current_version INTO old,counter FROM matching.current_results WHERE server_id=r.server_id AND identity=r.identity;
 IF old=r.id THEN RETURN false; END IF;
 counter:=coalesce(counter,0)+1;
 INSERT INTO matching.current_results VALUES(r.server_id,r.identity,r.id,counter)
 ON CONFLICT(server_id,identity) DO UPDATE SET result_id=excluded.result_id,current_version=excluded.current_version;
 changes:=ARRAY[CASE WHEN old IS NULL THEN 'created' ELSE 'replaced' END,'basis_changed'];
 IF old IS NULL OR (SELECT status FROM matching.result_revisions WHERE id=old)<>r.status THEN
  changes:=changes||ARRAY['status_changed',CASE r.status WHEN 'affected' THEN 'affected_confirmed'
   WHEN 'not_affected' THEN 'not_affected_confirmed' WHEN 'not_applicable' THEN 'lifecycle_excluded' ELSE 'unclear' END];
 END IF;
 FOREACH category IN ARRAY changes LOOP
 PERFORM automation.emit_event(gen_random_uuid(),'matching.'||category,1,'cve-matcher','server-cve',
 encode(sha256(convert_to(r.server_id::text||':'||r.identity,'UTF8')),'hex'),counter,
 jsonb_build_object('server_id',r.server_id,'snapshot_id',r.snapshot_id,'identity',r.identity,
 'enrichment_revision_id',r.enrichment_revision_id,'result_id',r.id,'rule_version',r.rule_version,
 'status',r.status,'current_version',counter),
 encode(sha256(convert_to(r.server_id::text||':'||r.identity||':'||counter::text||':'||category,'UTF8')),'hex'),p_correlation);
 END LOOP;
 RETURN true;
END $$;
GRANT EXECUTE ON FUNCTION matching.publish(uuid,uuid) TO matcher;
INSERT INTO automation.job_types(code,handler_role,producer_roles,runtime_seconds,max_attempts)
SELECT 'matching.'||x,'matcher',ARRAY['matcher','api_security','inventory_processor','enricher']::name[],3600,3
FROM unnest(ARRAY['evaluate_snapshot','evaluate_vulnerability','evaluate_candidate_batch','reconcile','backfill']) x;
-- Existing Phase-0 matching.run remains registered but is not silently repurposed.
INSERT INTO automation.event_types(code,producer_role,source)
SELECT 'matching.'||x,'matcher','cve-matcher' FROM unnest(ARRAY['created','replaced','basis_changed','status_changed','affected_confirmed','not_affected_confirmed','unclear','lifecycle_excluded']) x;
CREATE FUNCTION matching.schedule_inputs() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE kind text; payload jsonb;
BEGIN
 IF NEW.event_type='inventory.current_changed' AND NEW.source='inventory-processor' THEN
  kind:='matching.evaluate_snapshot'; payload:=jsonb_build_object('snapshot_id',NEW.payload->>'snapshot_id','event_id',NEW.id);
 ELSIF NEW.event_type IN ('cve.enrichment.created','cve.enrichment.changed','cve.enrichment.rejected','cve.enrichment.aliases_changed','cve.enrichment.affected_changed')
 AND NEW.source='cve-enricher' AND NEW.payload->>'identity' ~ '^CVE-[0-9]{4}-[0-9]{4,}$' THEN
  kind:='matching.evaluate_vulnerability'; payload:=jsonb_build_object('identity',NEW.payload->>'identity','enrichment_revision_id',NEW.payload->>'revision_id','event_id',NEW.id);
 ELSE RETURN NEW; END IF;
 PERFORM automation.enqueue_job(kind,1,payload,'matching-event:'||NEW.id::text,NEW.correlation_id,0,NULL,NULL,3,'matching-events',false);
 RETURN NEW;
END $$;
CREATE TRIGGER schedule_matching AFTER INSERT ON automation.event_outbox FOR EACH ROW EXECUTE FUNCTION matching.schedule_inputs();
CREATE VIEW matching.current_evaluations AS
 SELECT c.current_version,r.*,
 (s.snapshot_id=r.snapshot_id AND e.current_revision_id=r.enrichment_revision_id AND a.status='active') AS is_current
 FROM matching.current_results c JOIN matching.result_revisions r ON r.id=c.result_id
 JOIN inventory.servers a ON a.id=r.server_id
 LEFT JOIN inventory.server_current_snapshots s ON s.server_id=r.server_id
 JOIN cve.enrichment_identities e ON e.identity=r.identity;
GRANT SELECT ON matching.current_evaluations TO matcher,reporter,findings_writer;
CREATE FUNCTION matching.metrics() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
SELECT jsonb_build_object(
 'queued',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status IN ('queued','retry_pending')),
 'completed',(SELECT count(*) FROM matching.runs WHERE rule_version='matching-1' AND status='succeeded'),
 'failed',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status IN ('failed','timed_out')),
 'candidates',(SELECT count(*) FROM matching.candidates),'results',(SELECT count(*) FROM matching.result_revisions),
 'statuses',(SELECT coalesce(jsonb_object_agg(status,n),'{}') FROM (SELECT status,count(*) n FROM matching.current_evaluations GROUP BY status) x),
 'conflicts',(SELECT count(*) FROM matching.result_conflicts),
 'unmapped',(SELECT coalesce(sum(unmapped_count),0) FROM matching.indexed_revisions),
 'stale',(SELECT count(*) FROM matching.current_evaluations WHERE NOT is_current),
 'retry_count',(SELECT coalesce(sum(greatest(attempts-1,0)),0) FROM automation.jobs WHERE job_type LIKE 'matching.%'),
 'duration_ms',(SELECT coalesce(sum(a.duration_ms),0) FROM automation.job_attempts a JOIN automation.jobs j ON j.id=a.job_id WHERE j.job_type LIKE 'matching.%'),
 'running',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status='running'),
 'successful_jobs',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status='succeeded'),
 'oldest_job_seconds',(SELECT extract(epoch FROM clock_timestamp()-min(created_at)) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status IN ('queued','retry_pending')),
 'current_changes',(SELECT count(*) FROM automation.event_outbox WHERE source='cve-matcher' AND event_type IN ('matching.created','matching.replaced')),
 'outbox_backlog',(SELECT count(*) FROM automation.event_deliveries d JOIN automation.event_outbox e ON e.id=d.event_id WHERE e.source='cve-matcher' AND d.status NOT IN ('delivered','cancelled')),
 'unevaluable_ranges',(SELECT count(*) FROM matching.component_results WHERE decision->>'reason' IN ('unsupported_comparator','git_graph_unavailable','invalid_range','unsupported_cna_range')),
 'coverage',(SELECT jsonb_build_object('evaluated',count(*),'globally_complete',count(*) FILTER(WHERE (value->>'global_negative')::boolean)) FROM matching.coverage),
 'active_workers',(SELECT count(DISTINCT lease_owner) FROM automation.jobs WHERE job_type LIKE 'matching.%' AND status='running'));
$$;
GRANT EXECUTE ON FUNCTION matching.metrics() TO matcher,reporter,status_probe;
"""
