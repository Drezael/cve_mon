"""Include presentation/report FKs and remove erased identities from personal filters."""

from alembic import op

revision = "00047_erasure_presentation"
down_revision = "00046_permanent_server_delete"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Deleted identities must not return through presentation state")


DDL = r"""
CREATE FUNCTION inventory.strip_erased_ids(value jsonb,ids text[]) RETURNS jsonb
 LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE result jsonb; BEGIN
 IF jsonb_typeof(value)='string' AND EXISTS(SELECT 1 FROM unnest(ids) id WHERE strpos(value#>>'{}',id)>0)
 THEN RETURN NULL; END IF;
 IF jsonb_typeof(value)='object' THEN
  SELECT coalesce(jsonb_object_agg(k,v),'{}'::jsonb) INTO result FROM (
   SELECT e.key k,inventory.strip_erased_ids(e.value,ids) v FROM jsonb_each(value) e
   WHERE NOT EXISTS(SELECT 1 FROM unnest(ids) id WHERE strpos(e.key,id)>0)) projected WHERE v IS NOT NULL;
  RETURN result;
 ELSIF jsonb_typeof(value)='array' THEN
  SELECT coalesce(jsonb_agg(v ORDER BY position),'[]'::jsonb) INTO result FROM (
   SELECT inventory.strip_erased_ids(e.value,ids) v,e.position FROM jsonb_array_elements(value) WITH ORDINALITY e(value,position)) projected WHERE v IS NOT NULL;
  RETURN result;
 END IF;
 RETURN value;
END $$;
REVOKE ALL ON FUNCTION inventory.strip_erased_ids(jsonb,text[]) FROM PUBLIC;
DO $$ DECLARE fk record; definition text; patched text; BEGIN
 FOR fk IN SELECT conrelid::regclass AS rel,conname FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace
 WHERE contype='f' AND NOT c.condeferrable AND n.nspname IN ('dashboard','system','status','cve') LOOP
  EXECUTE format('ALTER TABLE %s ALTER CONSTRAINT %I DEFERRABLE INITIALLY IMMEDIATE',fk.rel,fk.conname);
 END LOOP;
 SELECT pg_get_functiondef('inventory.erase_server(uuid,uuid)'::regprocedure) INTO definition;
 patched:=replace(definition,
 'n.nspname IN (''security'',''inventory'',''matching'',''findings'',''automation'')',
 'n.nspname IN (''security'',''inventory'',''matching'',''findings'',''automation'',''dashboard'',''system'',''status'',''cve'')');
 IF patched=definition THEN RAISE EXCEPTION 'erasure FK patch did not apply'; END IF;
 patched:=replace(patched,' SET CONSTRAINTS ALL IMMEDIATE;',
 ' UPDATE dashboard.user_preferences SET preferences=inventory.strip_erased_ids(preferences,ARRAY(SELECT id FROM pg_temp.server_purge_ids)),
 version=version+1,updated_at=clock_timestamp() WHERE EXISTS(SELECT 1 FROM pg_temp.server_purge_ids ids WHERE strpos(preferences::text,ids.id)>0);
 SET CONSTRAINTS ALL IMMEDIATE;');
 EXECUTE patched;
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00046_permanent_server_delete','00047_erasure_presentation');
END $$;
"""
