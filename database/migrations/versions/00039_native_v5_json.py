"""Native V5 JSON with small revision handles and batched downstream indexing."""

from alembic import op

revision = "00039_native_v5_json"
down_revision = "00038_git_retry_and_matching"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)
    driver.execute(BACKFILL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use reviewed data-preserving backup/restore")


DDL = r"""
ALTER TABLE cve.source_revisions
 ADD git_commit text CHECK(git_commit ~ '^[0-9a-f]{40}$'),
 ADD git_path text CHECK(length(git_path) BETWEEN 1 AND 512),
 ADD git_blob_oid text CHECK(git_blob_oid ~ '^[0-9a-f]{40}$');
ALTER TABLE cve.enrichment_revisions
 ADD document_revision_id uuid REFERENCES cve.source_revisions(id),
 ADD document_present boolean,
 ADD CONSTRAINT native_document_binding CHECK(
  (document_revision_id IS NULL AND document_present IS NULL AND result->>'storage' IS DISTINCT FROM 'v5-json')
  OR (document_revision_id IS NOT NULL AND document_present IS NOT NULL AND result='{"storage":"v5-json"}'::jsonb));
ALTER TABLE cve.enrichment_revisions DROP CONSTRAINT enrichment_revisions_rule_version_check;
ALTER TABLE cve.enrichment_revisions ADD CHECK(rule_version IN ('enrichment-1','v5-json-1'));
CREATE VIEW cve.v5_revision_documents AS
 SELECT e.id,e.identity,e.document_revision_id AS source_revision_id,e.document_present,
 v.original_json AS document,v.git_commit,v.git_path,v.git_blob_oid,v.published_at,v.modified_at,
 v.source_status,e.created_at
 FROM cve.enrichment_revisions e JOIN cve.source_revisions v ON v.id=e.document_revision_id
 WHERE v.source_id='cve_list';
CREATE VIEW cve.v5_current_documents AS
 SELECT d.*,i.current_version FROM cve.enrichment_identities i
 JOIN cve.v5_revision_documents d ON d.id=i.current_revision_id;
GRANT SELECT ON cve.v5_revision_documents,cve.v5_current_documents TO matcher,findings_writer,api_security,reporter,enricher;
-- Read only fields needed by matching/priority across the wire, never duplicate them on disk.
CREATE FUNCTION cve.v5_projection(p_document jsonb,p_cvss boolean) RETURNS jsonb
 LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('cveMetadata',jsonb_build_object('state',p_document#>'{cveMetadata,state}'),
 'containers',jsonb_build_object('cna',jsonb_build_object(
  'affected',coalesce(p_document#>'{containers,cna,affected}','[]'::jsonb),
  'metrics',CASE WHEN p_cvss THEN coalesce(p_document#>'{containers,cna,metrics}','[]'::jsonb) ELSE '[]'::jsonb END,
  'providerMetadata',coalesce(p_document#>'{containers,cna,providerMetadata}','{}'::jsonb)),
 'adp',coalesce((SELECT jsonb_agg(jsonb_build_object(
  'affected',coalesce(value->'affected','[]'::jsonb),
  'metrics',CASE WHEN p_cvss THEN coalesce(value->'metrics','[]'::jsonb) ELSE '[]'::jsonb END,
  'providerMetadata',coalesce(value->'providerMetadata','{}'::jsonb)) ORDER BY ordinal)
 FROM jsonb_array_elements(coalesce(p_document#>'{containers,adp}','[]'::jsonb)) WITH ORDINALITY AS a(value,ordinal)),'[]'::jsonb)))
 $$;
REVOKE ALL ON FUNCTION cve.v5_projection(jsonb,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cve.v5_projection(jsonb,boolean) TO matcher,findings_writer,enricher,reporter;
CREATE INDEX source_revisions_v5_modified ON cve.source_revisions(modified_at DESC,id)
 WHERE source_id='cve_list';
CREATE INDEX source_revisions_v5_state ON cve.source_revisions(source_status,id)
 WHERE source_id='cve_list';
INSERT INTO automation.job_types(code,handler_role,producer_roles,runtime_seconds,max_attempts)
 VALUES('matching.index_v5_batch','matcher',ARRAY['importer','matcher']::name[],3600,3);

-- Importer can publish handles for its current source page, not arbitrary enrichment content.
CREATE FUNCTION cve.publish_v5(p_run uuid,p_ids text[])
 RETURNS TABLE(identity text,revision_id uuid,current_version bigint)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
#variable_conflict use_column
DECLARE jid uuid;
BEGIN
 IF session_user<>'importer' OR p_ids IS NULL OR cardinality(p_ids) NOT BETWEEN 1 AND 1000
 OR EXISTS(SELECT 1 FROM unnest(p_ids) x WHERE x IS NULL OR x !~ '^CVE-[0-9]{4}-[0-9]{4,}$') THEN
  RAISE EXCEPTION 'native publication denied' USING ERRCODE='42501'; END IF;
 SELECT r.job_id INTO jid FROM cve.import_runs r JOIN automation.jobs j ON j.id=r.job_id
 WHERE r.id=p_run AND r.source_id='cve_list' AND r.status='running' AND j.status='running'
 AND r.context#>>'{configuration,cve_list_transport}'='git';
 IF jid IS NULL THEN RAISE EXCEPTION 'running Git import required' USING ERRCODE='42501'; END IF;
 PERFORM 1 FROM cve.source_records r WHERE r.source_id='cve_list' AND r.external_id=ANY(p_ids)
 AND r.last_seen_run=p_run ORDER BY r.external_id FOR UPDATE;
 INSERT INTO cve.enrichment_identities(identity,kind)
 SELECT r.external_id,'cve' FROM cve.source_records r
 WHERE r.source_id='cve_list' AND r.external_id=ANY(p_ids) AND r.last_seen_run=p_run
 ON CONFLICT DO NOTHING;
 INSERT INTO cve.enrichment_revisions(identity,rule_version,input_fingerprint,result,job_id,document_revision_id,document_present)
 SELECT r.external_id,'v5-json-1',sha256(convert_to('v5-json-1:'||v.id::text||':'||r.present::text,'UTF8')),
 '{"storage":"v5-json"}'::jsonb,jid,v.id,r.present
 FROM cve.source_records r JOIN cve.source_revisions v ON v.id=r.current_revision_id
 WHERE r.source_id='cve_list' AND r.external_id=ANY(p_ids) AND r.last_seen_run=p_run
 ON CONFLICT(identity,rule_version,input_fingerprint) DO NOTHING;
 INSERT INTO cve.enrichment_inputs(enrichment_revision_id,source_revision_id)
 SELECT e.id,e.document_revision_id FROM cve.source_records r
 JOIN cve.enrichment_revisions e ON e.identity=r.external_id AND e.rule_version='v5-json-1'
 AND e.document_revision_id=r.current_revision_id AND e.document_present=r.present
 WHERE r.source_id='cve_list' AND r.external_id=ANY(p_ids) AND r.last_seen_run=p_run
 ON CONFLICT DO NOTHING;
 RETURN QUERY
 UPDATE cve.enrichment_identities i SET current_revision_id=e.id,current_version=i.current_version+1
 FROM cve.source_records r JOIN cve.enrichment_revisions e ON e.identity=r.external_id
 AND e.rule_version='v5-json-1' AND e.document_revision_id=r.current_revision_id AND e.document_present=r.present
 WHERE r.source_id='cve_list' AND r.external_id=ANY(p_ids) AND r.last_seen_run=p_run
 AND i.identity=r.external_id AND i.current_revision_id IS DISTINCT FROM e.id
 RETURNING i.identity,e.id,i.current_version;
END $$;
REVOKE ALL ON FUNCTION cve.publish_v5(uuid,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cve.publish_v5(uuid,text[]) TO importer;

-- Preserve historical normalized evidence. Its wide GIN index is not used by any runtime query.
DROP INDEX cve.enrichment_assertions_values;
DROP INDEX automation.jobs_cve_pipeline_status;
CREATE INDEX jobs_cve_pipeline_status ON automation.jobs(job_type,status)
 WHERE runtime_version=1 AND job_type IN (
 'cve.enrich.batch','cve.enrich.record','cve.enrich.reconcile','cve.enrich.backfill',
 'cve.epss.sync_daily','matching.index_v5_batch');
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('cve.dashboard_pipeline_status()'::regprocedure) INTO definition;
 definition:=replace(definition,'''processed_records'',i.processed_records,',
 '''indexed_records'',(SELECT count(*) FROM cve.enrichment_identities i JOIN matching.indexed_revisions m ON m.enrichment_revision_id=i.current_revision_id),''processed_records'',i.processed_records,');
 EXECUTE replace(definition,'''cve.enrich.batch''','''cve.enrich.batch'',''matching.index_v5_batch''');
 SELECT pg_get_functiondef('cve.dashboard_data_status()'::regprocedure) INTO definition;
 definition:=replace(definition,'''id'',s.id,''name'',s.name,''enabled'',s.enabled,',
 '''id'',s.id,''name'',s.name,''enabled'',s.enabled,
 ''git_commit'',(SELECT cursor->>''git_commit'' FROM cve.source_streams WHERE source_id=s.id AND stream=''main''),
 ''error_count'',coalesce((SELECT error_count FROM cve.import_runs WHERE source_id=s.id ORDER BY created_at DESC,id DESC LIMIT 1),0),');
 IF strpos(definition,'''git_commit''')=0 THEN RAISE EXCEPTION 'Unexpected data status function'; END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('cve.enricher_metrics()'::regprocedure) INTO definition;
 definition:=replace(definition,'''identities'',',
 '''native_documents'',(SELECT count(*) FROM cve.v5_current_documents),''identities'',');
 definition:=replace(definition,'NULLIF((SELECT count(*) FROM cve.enrichment_identities),0)',
 'NULLIF((SELECT count(*) FROM cve.enrichment_identities i JOIN cve.enrichment_revisions r ON r.id=i.current_revision_id WHERE r.document_revision_id IS NULL),0)');
 EXECUTE definition;
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 IF strpos(definition,'00038_git_retry_and_matching')=0 THEN RAISE EXCEPTION 'Unexpected sampler head'; END IF;
 EXECUTE replace(definition,'00038_git_retry_and_matching','00039_native_v5_json');
END $$;
"""

# Existing V5-only revisions can use their original JSON without changing any IDs.
# Mixed-source/ambiguous historical evidence is deliberately retained unchanged.
BACKFILL = r"""
SET LOCAL statement_timeout='15min';
SET LOCAL work_mem='64MB';
CREATE TEMP TABLE v5_handle_conversion ON COMMIT DROP AS
WITH inputs AS (
 SELECT enrichment_revision_id,(array_agg(source_revision_id))[1] AS source_revision_id
 FROM cve.enrichment_inputs GROUP BY enrichment_revision_id HAVING count(*)=1
), candidates AS (
 SELECT e.id,e.identity,v.id AS source_revision_id,e.created_at,
 (i.current_revision_id=e.id) AS is_current,
 sha256(convert_to('v5-json-1:'||v.id::text||':true','UTF8')) AS fingerprint
 FROM inputs p JOIN cve.enrichment_revisions e ON e.id=p.enrichment_revision_id
 JOIN cve.source_revisions v ON v.id=p.source_revision_id
 JOIN cve.enrichment_identities i ON i.identity=e.identity
 WHERE e.document_revision_id IS NULL AND v.source_id='cve_list'
 AND v.original_json#>>'{cveMetadata,cveId}'=e.identity
 AND e.result#>>'{lifecycle,value}' IN ('published','rejected')
 AND coalesce(e.result#>>'{kev,status}','unknown')='unknown'
 AND NOT EXISTS(SELECT 1 FROM cve.source_records r WHERE r.current_revision_id=v.id
  AND NOT r.present AND i.current_revision_id=e.id)
)
SELECT DISTINCT ON(identity,fingerprint) * FROM candidates
ORDER BY identity,fingerprint,is_current DESC,created_at DESC,id;
CREATE UNIQUE INDEX ON v5_handle_conversion(id);
ANALYZE v5_handle_conversion;
ALTER TABLE cve.enrichment_revisions DISABLE TRIGGER immutable;
UPDATE cve.enrichment_revisions e SET result='{"storage":"v5-json"}'::jsonb,
 document_revision_id=t.source_revision_id,document_present=true,
 rule_version='v5-json-1',input_fingerprint=t.fingerprint
FROM v5_handle_conversion t WHERE e.id=t.id;
ALTER TABLE cve.enrichment_revisions ENABLE TRIGGER immutable;
ALTER TABLE cve.enrichment_assertions DISABLE TRIGGER immutable;
DELETE FROM cve.enrichment_assertions a USING v5_handle_conversion t WHERE a.enrichment_revision_id=t.id;
ALTER TABLE cve.enrichment_assertions ENABLE TRIGGER immutable;
-- Older Git imports retained commit/path in their run and observation rather than columns.
ALTER TABLE cve.source_revisions DISABLE TRIGGER immutable;
UPDATE cve.source_revisions v SET git_commit=r.progress#>>'{git,head}',git_path=o.position
FROM cve.import_runs r,cve.source_observations o
WHERE v.source_id='cve_list' AND v.git_commit IS NULL AND v.run_id=r.id
 AND r.progress#>>'{git,head}' ~ '^[0-9a-f]{40}$'
 AND o.run_id=v.run_id AND o.record_id=v.record_id AND o.revision_id=v.id
 AND o.position ~ '^cves/[0-9]{4}/[0-9]+xxx/CVE-[0-9]{4}-[0-9]+[.]json$';
ALTER TABLE cve.source_revisions ENABLE TRIGGER immutable;
"""
