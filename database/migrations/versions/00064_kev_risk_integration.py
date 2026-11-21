"""Optional CISA KEV updates through n8n; native V5 risk stays separate from documents."""

from alembic import op

revision = "00064_kev_risk_integration"
down_revision = "00063_bounded_server_erasure"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)
    definition = driver.execute(
        "SELECT pg_get_functiondef('cve.schedule_import(text,text,jsonb,text,uuid)'::regprocedure)"
    ).fetchone()[0]
    start = definition.index(" IF session_user='workflow_control' AND (")
    end = definition.index(" IF session_user NOT IN", start)
    definition = (
        definition[:start]
        + """
 IF session_user='workflow_control' AND (NOT cve.monitor_source_configuration(p_context->'configuration')
 OR NOT (p_context->'configuration'->'enabled' ? p_source))
 THEN RAISE EXCEPTION 'Only V5 Git and optional CISA KEV authorized' USING ERRCODE='42501'; END IF;
"""
        + definition[end:]
    )
    driver.execute(definition, prepare=False)
    definition = driver.execute(
        "SELECT pg_get_functiondef('cve.dashboard_request_update(uuid,uuid,jsonb)'::regprocedure)"
    ).fetchone()[0]
    before = "p_config->'enabled' IS DISTINCT FROM '[\"cve_list\"]'::jsonb"
    assert before in definition
    driver.execute(
        definition.replace(before, "NOT cve.monitor_source_configuration(p_config)"), prepare=False
    )
    definition = driver.execute(
        "SELECT pg_get_functiondef('automation.workflow_tick_v59(text,text,text)'::regprocedure)"
    ).fetchone()[0]
    definition = definition.replace(
        "  IF active IS NULL THEN",
        """  IF EXISTS(SELECT 1 FROM cve.sources src WHERE src.enabled AND cfg.source_config->'enabled' ? src.id
 AND NOT EXISTS(SELECT 1 FROM cve.import_run_status r WHERE r.source_id=src.id AND r.effective_status IN ('planned','running'))) THEN""",
    )
    driver.execute(definition, prepare=False)
    definition = driver.execute(
        "SELECT pg_get_functiondef('cve.source_enrichment_event()'::regprocedure)"
    ).fetchone()[0]
    definition = definition.replace(
        " IF EXISTS(SELECT 1 FROM cve.source_records WHERE id=rid AND external_id<>'catalog') THEN",
        """ IF EXISTS(SELECT 1 FROM cve.source_records r WHERE id=rid AND external_id<>'catalog'
 AND NOT (r.source_id='cisa_kev' AND EXISTS(SELECT 1 FROM cve.v5_current_documents d WHERE d.identity=r.external_id))) THEN""",
    )
    needle = " ELSIF NEW.event_type='cve.source.completed'"
    assert needle in definition
    # Always refresh finding risk on a verified complete catalog, even after unchanged bytes.
    definition = definition.replace(
        needle,
        """ ELSIF NEW.event_type='cve.source.completed' AND NEW.payload->>'source_id'='cisa_kev' THEN
 PERFORM automation.enqueue_job('findings.refresh_priority',1,'{}',NEW.id::text||':kev',NEW.correlation_id,0,NULL,NULL,3,'kev-risk',false);
 END IF;
 IF NEW.event_type='cve.source.completed'""",
        1,
    )
    driver.execute(definition, prepare=False)
    driver.execute(
        r"""
UPDATE automation.job_types SET producer_roles=array_append(producer_roles,'workflow_control'::name)
WHERE code='cve.import.cisa_kev' AND NOT ('workflow_control'=ANY(producer_roles));
UPDATE automation.job_types SET producer_roles=array_append(producer_roles,'importer'::name)
WHERE code='findings.refresh_priority' AND NOT ('importer'=ANY(producer_roles));
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00063_bounded_server_erasure','00064_kev_risk_integration');
END $$;
""",
        prepare=False,
    )


def downgrade() -> None:
    raise RuntimeError("Preserve KEV risk provenance and native V5 documents")


DDL = r"""
CREATE FUNCTION cve.monitor_source_configuration(p_config jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT CASE WHEN jsonb_typeof(p_config->'enabled')='array' THEN coalesce(
 p_config->'enabled' @> '["cve_list"]'::jsonb
 AND p_config->'enabled' <@ '["cve_list","cisa_kev"]'::jsonb
 AND jsonb_array_length(p_config->'enabled')=(SELECT count(DISTINCT v) FROM jsonb_array_elements_text(p_config->'enabled') v)
 AND p_config->>'cve_list_transport'='git' AND p_config->'epss_enabled'='false'::jsonb,false) ELSE false END
$$;
REVOKE ALL ON FUNCTION cve.monitor_source_configuration(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cve.monitor_source_configuration(jsonb) TO api_security,workflow_control;
CREATE FUNCTION cve.kev_risk(p_identity text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
WITH catalog AS MATERIALIZED (
 SELECT s.last_complete_run,s.last_success_at,s.cursor->>'catalog_version' AS version,o.revision_id
 FROM cve.source_streams s JOIN cve.source_records r ON r.source_id=s.source_id AND r.external_id='catalog'
 JOIN cve.source_observations o ON o.run_id=s.last_complete_run AND o.record_id=r.id
 WHERE s.source_id='cisa_kev' AND s.stream='main'
), evaluated AS (
 SELECT c.*,coalesce(c.last_success_at>=statement_timestamp()-interval '72 hours',false) AS current,
 entry.revision_id AS entry_revision,entry.due_date
 FROM catalog c LEFT JOIN LATERAL (
 SELECT o.revision_id,v.original_json->>'dueDate' AS due_date FROM cve.source_records r
 JOIN cve.source_observations o ON o.record_id=r.id AND o.run_id=c.last_complete_run
 JOIN cve.source_revisions v ON v.id=o.revision_id
 WHERE r.source_id='cisa_kev' AND r.external_id=p_identity
 ) entry ON true
)
SELECT coalesce((SELECT jsonb_build_object(
 'status',CASE WHEN NOT current THEN 'unknown' WHEN entry_revision IS NOT NULL THEN 'present' ELSE 'absent' END,
 'is_current',current,'due_date',CASE WHEN current THEN due_date END,
 'reason',CASE WHEN current THEN 'complete_catalog' ELSE 'stale_catalog' END,
 'catalog_revision_id',revision_id,'catalog_version',version,'last_success_at',last_success_at,
 'entry_revision_id',entry_revision) FROM evaluated),
 '{"status":"unknown","is_current":false,"reason":"no_complete_catalog","due_date":null}'::jsonb)
$$;
REVOKE ALL ON FUNCTION cve.kev_risk(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cve.kev_risk(text) TO findings_writer,matcher,enricher,api_security,reporter;
"""
