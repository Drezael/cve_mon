"""Optional daily EPSS through the central n8n update command and existing findings events."""

from alembic import op

revision = "00065_epss_workflow_integration"
down_revision = "00064_kev_risk_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)
    definition = driver.execute(
        "SELECT pg_get_functiondef('cve.dashboard_request_update(uuid,uuid,jsonb)'::regprocedure)"
    ).fetchone()[0]
    guard = " OR p_config->>'epss_enabled' IS DISTINCT FROM 'false'"
    assert guard in definition
    driver.execute(definition.replace(guard, ""), prepare=False)
    definition = driver.execute(
        "SELECT pg_get_functiondef('cve.execute_queued_update(uuid,uuid,jsonb)'::regprocedure)"
    ).fetchone()[0]
    needle = (
        " IF j.id IS NULL THEN\n  SELECT * INTO j FROM automation.enqueue_job('cve.epss.sync_daily'"
    )
    assert needle in definition
    definition = definition.replace(
        needle,
        """ IF j.id IS NULL AND (cve.epss_due() OR EXISTS(
 SELECT 1 FROM automation.n8n_queue WHERE correlation_id=p_key AND kind='command'
 AND message_type='cve.refresh' AND actor_id IS NOT NULL)) THEN
  SELECT * INTO j FROM automation.enqueue_job('cve.epss.sync_daily'""",
    )
    needle = " result:=result||jsonb_build_array(jsonb_build_object('source','epss','id',j.id));"
    assert needle in definition
    definition = definition.replace(needle, " IF j.id IS NOT NULL THEN" + needle + " END IF;")
    driver.execute(definition, prepare=False)
    definition = driver.execute(
        "SELECT pg_get_functiondef('automation.workflow_tick_v59(text,text,text)'::regprocedure)"
    ).fetchone()[0]
    needle = "r.effective_status IN ('planned','running'))) THEN"
    assert needle in definition
    definition = definition.replace(
        needle,
        """r.effective_status IN ('planned','running')))
 OR (cfg.source_config->'epss_enabled'='true'::jsonb AND cve.epss_due()) THEN""",
        1,
    )
    driver.execute(definition, prepare=False)
    definition = driver.execute(
        "SELECT pg_get_functiondef('automation.n8n_decide_v48(uuid,uuid,text,text,text)'::regprocedure)"
    ).fetchone()[0]
    start = definition.index("  IF item.actor_id IS NULL THEN")
    end = definition.index("  ELSE\n   answer:=cve.execute_queued_update", start)
    definition = definition[:start] + AUTOMATIC + definition[end:]
    driver.execute(definition, prepare=False)
    driver.execute(
        """
UPDATE automation.job_types SET producer_roles=array_append(producer_roles,'workflow_control'::name)
WHERE code='cve.epss.sync_daily' AND NOT ('workflow_control'=ANY(producer_roles));
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00064_kev_risk_integration','00065_epss_workflow_integration');
END $$;
""",
        prepare=False,
    )


def downgrade() -> None:
    raise RuntimeError("Preserve EPSS history and n8n update provenance")


DDL = r"""
CREATE OR REPLACE FUNCTION cve.monitor_source_configuration(p_config jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT CASE WHEN jsonb_typeof(p_config->'enabled')='array' THEN coalesce(
 p_config->'enabled' @> '["cve_list"]'::jsonb
 AND p_config->'enabled' <@ '["cve_list","cisa_kev"]'::jsonb
 AND jsonb_array_length(p_config->'enabled')=(SELECT count(DISTINCT v) FROM jsonb_array_elements_text(p_config->'enabled') v)
 AND p_config->>'cve_list_transport'='git'
 AND jsonb_typeof(p_config->'epss_enabled')='boolean',false) ELSE false END
$$;
CREATE FUNCTION cve.epss_due() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT NOT EXISTS(SELECT 1 FROM cve.epss_current_dataset h JOIN cve.epss_import_runs r ON r.id=h.dataset_id
 WHERE r.status='completed' AND r.score_date>=(statement_timestamp() AT TIME ZONE 'UTC')::date)
 AND NOT EXISTS(SELECT 1 FROM automation.jobs WHERE job_type='cve.epss.sync_daily'
 AND status IN ('pending','queued','retry_pending','running'))
$$;
REVOKE ALL ON FUNCTION cve.epss_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cve.epss_due() TO workflow_control;
"""

AUTOMATIC = r"""  IF item.actor_id IS NULL THEN
   IF NOT cve.monitor_source_configuration(item.payload->'configuration') THEN
    RAISE EXCEPTION 'invalid scheduled update configuration' USING ERRCODE='42501'; END IF;
   answer:='[]'::jsonb;
   FOR stage IN SELECT id FROM cve.sources WHERE enabled AND item.payload->'configuration'->'enabled' ? id ORDER BY id LOOP
    SELECT id INTO active FROM cve.import_run_status WHERE source_id=stage AND effective_status IN ('planned','running') ORDER BY created_at DESC LIMIT 1;
    IF active IS NULL THEN
     active:=cve.schedule_import(stage,CASE WHEN EXISTS(SELECT 1 FROM cve.import_runs WHERE source_id=stage AND status='completed') THEN 'incremental' ELSE 'initial' END,
      jsonb_build_object('configuration',item.payload->'configuration'),item.deduplication_key,item.correlation_id);
    END IF;
    answer:=answer||jsonb_build_array(jsonb_build_object('source',stage,'id',active));
   END LOOP;
   IF item.payload->'configuration'->'epss_enabled'='true'::jsonb THEN
    SELECT id INTO active FROM automation.jobs WHERE job_type='cve.epss.sync_daily'
     AND status IN ('pending','queued','retry_pending','running') ORDER BY created_at DESC LIMIT 1;
    IF active IS NULL AND cve.epss_due() THEN
     SELECT id INTO active FROM automation.enqueue_job('cve.epss.sync_daily',1,'{}'::jsonb,
      item.deduplication_key,item.correlation_id,0,NULL,NULL,3,'cve-data',false);
    END IF;
    IF active IS NOT NULL THEN answer:=answer||jsonb_build_array(jsonb_build_object('source','epss','id',active)); END IF;
   END IF;
"""
