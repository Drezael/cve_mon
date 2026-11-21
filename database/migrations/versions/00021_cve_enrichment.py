"""Versioned enrichment, immutable evidence and atomic EPSS datasets."""

from alembic import op

revision = "00021_cve_enrichment"
down_revision = "00020_cve_importer"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Data-preserving rollback requires reviewed backup/restore")


DDL = r"""
-- The old source-specific enrichments table remains historical; no raw-table write grants.
REVOKE INSERT,UPDATE ON cve.enrichments,cve.records FROM enricher;
-- Row-locking needs UPDATE privilege in PostgreSQL; narrowly scoped definers expose
-- locks only, keeping the enricher's source-table grants strictly read-only.
CREATE INDEX source_records_external ON cve.source_records(external_id,id);
CREATE INDEX source_records_current ON cve.source_records(current_revision_id);
CREATE FUNCTION cve.lock_enrichment_inputs(p_identity text) RETURNS SETOF uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'enricher' THEN RAISE EXCEPTION 'context lock denied' USING ERRCODE='42501'; END IF;
 RETURN QUERY WITH ids AS (
 SELECT id FROM cve.source_records WHERE external_id=p_identity AND external_id<>'catalog'
 UNION SELECT r0.id FROM cve.source_record_identifiers a JOIN cve.source_records r0 ON r0.current_revision_id=a.revision_id WHERE a.identifier=p_identity
 ) SELECT r.id FROM ids JOIN cve.source_records r ON r.id=ids.id ORDER BY r.source_id,r.external_id LIMIT 2001 FOR SHARE OF r;
 PERFORM 1 FROM cve.source_streams WHERE source_id='cisa_kev' AND stream='main' FOR SHARE;
END $$;
GRANT EXECUTE ON FUNCTION cve.lock_enrichment_inputs(text) TO enricher;
CREATE TABLE cve.enrichment_identities (
 identity text PRIMARY KEY CHECK(identity ~ '^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,255}$'),
 kind text NOT NULL CHECK(kind IN ('cve','advisory')),current_revision_id uuid,current_version bigint NOT NULL DEFAULT 0 CHECK(current_version>=0),
 CHECK((kind='cve')=(identity ~ '^CVE-[0-9]{4}-[0-9]{4,}$'))
);
CREATE TABLE cve.enrichment_revisions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),identity text NOT NULL REFERENCES cve.enrichment_identities(identity),
 rule_version text NOT NULL CHECK(rule_version='enrichment-1'),input_fingerprint bytea NOT NULL CHECK(octet_length(input_fingerprint)=32),
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object'),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 job_id uuid NOT NULL REFERENCES automation.jobs(id),UNIQUE(identity,rule_version,input_fingerprint),UNIQUE(id,identity)
);
ALTER TABLE cve.enrichment_identities ADD FOREIGN KEY(current_revision_id,identity) REFERENCES cve.enrichment_revisions(id,identity) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE cve.enrichment_inputs (
 enrichment_revision_id uuid NOT NULL REFERENCES cve.enrichment_revisions(id),
 source_revision_id uuid NOT NULL REFERENCES cve.source_revisions(id),PRIMARY KEY(enrichment_revision_id,source_revision_id)
);
CREATE TABLE cve.enrichment_assertions (
 enrichment_revision_id uuid NOT NULL REFERENCES cve.enrichment_revisions(id),category text NOT NULL,
 position integer NOT NULL CHECK(position>=0),value jsonb NOT NULL,
 source_revision_id uuid REFERENCES cve.source_revisions(id),PRIMARY KEY(enrichment_revision_id,category,position)
);
CREATE INDEX enrichment_assertions_category ON cve.enrichment_assertions(category,enrichment_revision_id);
CREATE INDEX enrichment_assertions_values ON cve.enrichment_assertions USING gin(value jsonb_path_ops);
CREATE INDEX enrichment_input_source ON cve.enrichment_inputs(source_revision_id,enrichment_revision_id);
CREATE FUNCTION cve.assert_enrichment_origin() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.source_revision_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM cve.enrichment_inputs WHERE enrichment_revision_id=NEW.enrichment_revision_id AND source_revision_id=NEW.source_revision_id) THEN
 RAISE EXCEPTION 'unbound enrichment evidence' USING ERRCODE='23514'; END IF;RETURN NEW;
END $$;
CREATE TRIGGER enrichment_assertion_origin BEFORE INSERT ON cve.enrichment_assertions FOR EACH ROW EXECUTE FUNCTION cve.assert_enrichment_origin();
DO $$ DECLARE name text;BEGIN FOREACH name IN ARRAY ARRAY['enrichment_revisions','enrichment_inputs','enrichment_assertions'] LOOP
 EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON cve.%I FOR EACH ROW EXECUTE FUNCTION system.append_only()',name);END LOOP;END $$;
CREATE VIEW cve.current_enrichment AS SELECT q.*,CASE WHEN q.kev_is_current THEN q.result#>>'{kev,status}' ELSE 'unknown' END AS kev_status FROM (SELECT i.kind,i.current_version,r.*,
 COALESCE((SELECT s.last_success_at>=clock_timestamp()-make_interval(hours=>COALESCE((r.result#>>'{kev,max_age_hours}')::int,72))
 AND EXISTS(SELECT 1 FROM cve.source_observations o WHERE o.run_id=s.last_complete_run AND o.revision_id=(r.result#>>'{kev,catalog_revision_id}')::uuid)
 FROM cve.source_streams s WHERE s.source_id='cisa_kev' AND s.stream='main'),false) AS kev_is_current
 FROM cve.enrichment_identities i JOIN cve.enrichment_revisions r ON r.id=i.current_revision_id) q;
"""
DDL += r"""
CREATE TABLE cve.epss_import_runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),score_date date NOT NULL,model_version text NOT NULL CHECK(model_version ~ '^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}$'),
 wire_sha256 bytea NOT NULL CHECK(octet_length(wire_sha256)=32),source_url text NOT NULL CHECK(source_url ~ '^https://epss[.]empiricalsecurity[.]com/epss_scores-'),
 status text NOT NULL DEFAULT 'staged' CHECK(status IN ('staged','completed','failed')),row_count bigint NOT NULL DEFAULT 0,
 imported_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz,
 UNIQUE(score_date,model_version,wire_sha256),UNIQUE(id,score_date,model_version)
);
CREATE TABLE cve.epss_daily_scores (
 dataset_id uuid NOT NULL,cve_id text NOT NULL CHECK(cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),score_date date NOT NULL,model_version text NOT NULL,
 score numeric(20,18) NOT NULL CHECK(score BETWEEN 0 AND 1),percentile numeric(20,18) NOT NULL CHECK(percentile BETWEEN 0 AND 1),
 FOREIGN KEY(dataset_id,score_date,model_version) REFERENCES cve.epss_import_runs(id,score_date,model_version),PRIMARY KEY(dataset_id,cve_id)
);
CREATE INDEX epss_cve_history ON cve.epss_daily_scores(cve_id,score_date DESC);
CREATE TABLE cve.epss_current_dataset(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),dataset_id uuid NOT NULL REFERENCES cve.epss_import_runs(id),current_version bigint NOT NULL DEFAULT 1 CHECK(current_version>0));
CREATE FUNCTION cve.check_epss_score_staging() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN IF NOT EXISTS(SELECT 1 FROM cve.epss_import_runs WHERE id=NEW.dataset_id AND status IN ('staged','failed')) THEN
 RAISE EXCEPTION 'sealed EPSS dataset' USING ERRCODE='23514';END IF;RETURN NEW;END $$;
CREATE TRIGGER epss_score_staging BEFORE INSERT ON cve.epss_daily_scores FOR EACH ROW EXECUTE FUNCTION cve.check_epss_score_staging();
CREATE TRIGGER epss_scores_immutable BEFORE UPDATE OR DELETE ON cve.epss_daily_scores FOR EACH ROW EXECUTE FUNCTION system.append_only();
CREATE TRIGGER epss_dataset_sealed BEFORE UPDATE OR DELETE ON cve.epss_import_runs FOR EACH ROW WHEN(OLD.status='completed') EXECUTE FUNCTION system.append_only();
CREATE FUNCTION cve.check_epss_head() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' AND (SELECT score_date FROM cve.epss_import_runs WHERE id=NEW.dataset_id)<(SELECT score_date FROM cve.epss_import_runs WHERE id=OLD.dataset_id) THEN
 RAISE EXCEPTION 'EPSS current date regression' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM cve.epss_import_runs r WHERE r.id=NEW.dataset_id AND r.status='completed' AND r.row_count>0 AND r.row_count=(SELECT count(*) FROM cve.epss_daily_scores WHERE dataset_id=r.id)) THEN
 RAISE EXCEPTION 'incomplete EPSS dataset' USING ERRCODE='23514'; END IF;RETURN NEW;END $$;
CREATE TRIGGER epss_head_complete BEFORE INSERT OR UPDATE ON cve.epss_current_dataset FOR EACH ROW EXECUTE FUNCTION cve.check_epss_head();
CREATE VIEW cve.current_epss_scores AS SELECT s.*,r.imported_at,(current_date-r.score_date) AS age_days,(current_date-r.score_date>2) AS is_stale FROM cve.epss_current_dataset h JOIN cve.epss_import_runs r ON r.id=h.dataset_id JOIN cve.epss_daily_scores s ON s.dataset_id=r.id;
GRANT SELECT,INSERT,UPDATE ON cve.enrichment_identities,cve.epss_import_runs,cve.epss_current_dataset TO enricher;
GRANT SELECT,INSERT ON cve.enrichment_revisions,cve.enrichment_inputs,cve.enrichment_assertions,cve.epss_daily_scores TO enricher;
GRANT SELECT ON cve.enrichment_identities,cve.enrichment_revisions,cve.enrichment_inputs,cve.enrichment_assertions,cve.current_enrichment,cve.epss_import_runs,cve.epss_daily_scores,cve.epss_current_dataset,cve.current_epss_scores TO enricher,reporter,matcher;
GRANT SELECT ON cve.source_presence,cve.source_leases TO enricher;
GRANT EXECUTE ON FUNCTION cve.jsonb_sha256(jsonb) TO enricher;
INSERT INTO automation.job_types(code,handler_role,producer_roles,runtime_seconds,max_attempts)
SELECT name,'enricher',ARRAY['api_security','enricher','importer']::name[],3600,3 FROM unnest(ARRAY['cve.enrich.record','cve.enrich.backfill','cve.epss.sync_daily','cve.enrich.reconcile']) name;
INSERT INTO automation.event_types(code,producer_role,source)
SELECT 'cve.enrichment.'||kind,'enricher','cve-enricher' FROM unnest(ARRAY['created','changed','rejected','aliases_changed','affected_changed','cvss_changed','kev_changed','epss_updated']) kind;
CREATE INDEX enrichment_pending_identity ON automation.jobs((payload->>'identity')) WHERE job_type='cve.enrich.record' AND status IN ('queued','retry_pending');
CREATE FUNCTION cve.enqueue_enrichment(p_identity text,p_key text,p_correlation uuid) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE jid uuid;BEGIN
 IF session_user NOT IN ('enricher','api_security','importer') OR p_identity !~ '^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,255}$' OR p_key IS NULL OR length(p_key) NOT BETWEEN 1 AND 1024 THEN RAISE EXCEPTION 'enrichment enqueue denied' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_identity,1601));
 SELECT id INTO jid FROM automation.jobs WHERE job_type='cve.enrich.record' AND status IN ('queued','retry_pending') AND payload->>'identity'=p_identity ORDER BY created_at LIMIT 1 FOR UPDATE;
 IF jid IS NOT NULL THEN RETURN jid; END IF;
 SELECT id INTO jid FROM automation.enqueue_job('cve.enrich.record',1,jsonb_build_object('identity',p_identity,'rule_version','enrichment-1'),encode(sha256(convert_to(p_key,'UTF8')),'hex'),p_correlation,0,NULL,NULL,3,'enrichment',false);
 RETURN jid;END $$;
GRANT EXECUTE ON FUNCTION cve.enqueue_enrichment(text,text,uuid) TO enricher,api_security,importer;
CREATE FUNCTION cve.source_enrichment_event() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target text;rid uuid;BEGIN
 IF NEW.source<>'cve-importer' OR NEW.runtime_version<>1 THEN RETURN NEW;END IF;
 IF NEW.event_type IN ('cve.source.new','cve.source.changed','cve.source.withdrawn','cve.source.removed') AND NEW.payload->>'record_id' IS NOT NULL THEN
 rid:=(NEW.payload->>'record_id')::uuid;
 IF EXISTS(SELECT 1 FROM cve.source_records WHERE id=rid AND external_id<>'catalog') THEN
 PERFORM automation.enqueue_job('cve.enrich.reconcile',1,jsonb_build_object('record_id',rid,'event_id',NEW.id),NEW.id::text,NEW.correlation_id,0,NULL,NULL,3,'source-change',false);
 END IF;
 ELSIF NEW.event_type='cve.source.completed' AND NEW.payload->>'source_id'='cisa_kev' AND EXISTS(SELECT 1 FROM cve.import_runs WHERE id=(NEW.payload->>'run_id')::uuid AND new_count+changed_count>0) THEN
 PERFORM automation.enqueue_job('cve.enrich.reconcile',1,'{}',NEW.id::text,NEW.correlation_id,0,NULL,NULL,3,'kev-refresh',false);
 END IF;RETURN NEW;END $$;
CREATE TRIGGER source_enrichment_queue AFTER INSERT ON automation.event_outbox FOR EACH ROW EXECUTE FUNCTION cve.source_enrichment_event();
CREATE FUNCTION cve.enricher_metrics() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
SELECT jsonb_build_object('identities',(SELECT count(*) FROM cve.enrichment_identities),'revisions',(SELECT count(*) FROM cve.enrichment_revisions),'conflicts',(SELECT count(*) FROM cve.enrichment_assertions WHERE category='conflicts'),'current_epss',(SELECT jsonb_build_object('date',r.score_date,'model',r.model_version,'rows',r.row_count,'age_days',current_date-r.score_date) FROM cve.epss_current_dataset h JOIN cve.epss_import_runs r ON r.id=h.dataset_id),'queued',(SELECT count(*) FROM automation.jobs WHERE job_type LIKE 'cve.enrich.%' AND status IN ('queued','running','retry_pending')))
$$;
GRANT EXECUTE ON FUNCTION cve.enricher_metrics() TO enricher,reporter,status_probe;
"""
