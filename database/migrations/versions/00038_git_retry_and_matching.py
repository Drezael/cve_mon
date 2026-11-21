"""Retry invalid Git files without rescanning valid records; one matching job per CVE version."""

from alembic import op

revision = "00038_git_retry_and_matching"
down_revision = "00037_git_collection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use reviewed data-preserving backup/restore")


DDL = r"""
CREATE OR REPLACE FUNCTION matching.schedule_inputs() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE kind text; payload jsonb; k text;
BEGIN
 IF NEW.event_type='inventory.current_changed' AND NEW.source='inventory-processor' THEN
  kind:='matching.evaluate_snapshot'; payload:=jsonb_build_object('snapshot_id',NEW.payload->>'snapshot_id','event_id',NEW.id);
  k:='matching-event:'||NEW.id::text;
 ELSIF NEW.event_type IN ('cve.enrichment.created','cve.enrichment.changed','cve.enrichment.rejected','cve.enrichment.aliases_changed','cve.enrichment.affected_changed')
 AND NEW.source='cve-enricher' AND NEW.payload->>'identity' ~ '^CVE-[0-9]{4}-[0-9]{4,}$' THEN
  kind:='matching.evaluate_vulnerability';
  payload:=jsonb_build_object('identity',NEW.payload->>'identity','enrichment_revision_id',NEW.payload->>'revision_id','event_id',NEW.id);
  k:=CASE WHEN NEW.payload->>'current_version' IS NOT NULL THEN
   'matching-version:'||encode(sha256(convert_to((NEW.payload->>'identity')||':'||(NEW.payload->>'current_version'),'UTF8')),'hex')
   ELSE 'matching-event:'||NEW.id::text END;
  IF EXISTS(SELECT 1 FROM automation.jobs WHERE runtime_version=1 AND job_type=kind AND idempotency_key=k)
   THEN RETURN NEW; END IF;
 ELSE RETURN NEW; END IF;
 PERFORM automation.enqueue_job(kind,1,payload,k,NEW.correlation_id,0,NULL,NULL,3,'matching-events',false);
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION findings.schedule_event() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE kind text; payload jsonb; k text;
BEGIN
 IF NEW.source='cve-matcher' AND NEW.event_type IN ('matching.created','matching.replaced') THEN
  kind:='findings.consume_matching_event';payload:=jsonb_build_object('event_id',NEW.id);
  k:='finding-event:'||NEW.id::text;
 ELSIF NEW.source='cve-enricher' AND NEW.event_type IN ('cve.enrichment.cvss_changed','cve.enrichment.kev_changed','cve.enrichment.epss_updated') THEN
  IF NEW.payload->>'identity' ~ '^CVE-[0-9]{4}-[0-9]{4,}$' THEN
   IF NOT EXISTS(SELECT 1 FROM findings.findings WHERE model_version=2 AND cve_id=NEW.payload->>'identity')
    THEN RETURN NEW; END IF;
   payload:=jsonb_build_object('identity',NEW.payload->>'identity');
   k:=CASE WHEN NEW.payload->>'current_version' IS NOT NULL THEN
    'finding-version:'||encode(sha256(convert_to((NEW.payload->>'identity')||':'||(NEW.payload->>'current_version'),'UTF8')),'hex')
    ELSE 'finding-event:'||NEW.id::text END;
  ELSE
   -- A global EPSS refresh remains scheduled: finding creation may overlap dataset publication.
   payload:='{}'::jsonb;k:='finding-event:'||NEW.id::text;
  END IF;
  kind:='findings.refresh_priority';
  IF EXISTS(SELECT 1 FROM automation.jobs WHERE runtime_version=1 AND job_type=kind AND idempotency_key=k)
   THEN RETURN NEW; END IF;
 ELSE RETURN NEW; END IF;
 PERFORM automation.enqueue_job(kind,1,payload,k,NEW.correlation_id,0,NULL,NULL,3,'findings-events',false);
 RETURN NEW;
END $$;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('cve.dashboard_request_update(uuid,uuid,jsonb)'::regprocedure) INTO definition;
 definition:=replace(definition,
 'EXISTS(SELECT 1 FROM cve.import_runs WHERE source_id=src AND status=''completed'')',
 'EXISTS(SELECT 1 FROM cve.import_runs WHERE source_id=src AND
 (status=''completed'' OR (src=''cve_list'' AND p_config->>''cve_list_transport''=''git''
 AND status=''partial'' AND progress->''git''->>''head'' IS NOT NULL
 AND progress->''git''->>''offset''=progress->''git''->>''count'')))');
 IF strpos(definition,'progress->''git''')=0 THEN RAISE EXCEPTION 'Unexpected refresh function'; END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 IF strpos(definition,'00037_git_collection')=0 THEN RAISE EXCEPTION 'Unexpected sampler head'; END IF;
 EXECUTE replace(definition,'00037_git_collection','00038_git_retry_and_matching');
END $$;
"""
