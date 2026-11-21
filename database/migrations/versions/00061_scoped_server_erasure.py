"""Index erasure references and bound the global critical section to the final delete."""

import hashlib

from alembic import op
from psycopg import sql

revision = "00061_scoped_server_erasure"
down_revision = "00060_transient_import_recovery"
branch_labels = None
depends_on = None

SOFT_TABLES = (
    "automation.jobs",
    "automation.event_outbox",
    "automation.runtime_actions",
    "automation.notification_audit",
    "automation.n8n_queue",
    "security.audit_log",
)


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(SETUP, prepare=False)
    indexes: list[tuple[str, str, str, str]] = []
    for table in SOFT_TABLES:
        expression = driver.execute(
            "SELECT inventory.erasure_expression(%s::regclass,'')", (table,)
        ).fetchone()[0]
        schema, name = table.split(".")
        indexes.append((schema, "purge_refs_" + name, table, "USING gin (" + expression + ")"))
    missing = driver.execute(r"""
      SELECT n.nspname,c.relname,fk.conname,
       string_agg(quote_ident(a.attname),',' ORDER BY k.position)
      FROM pg_constraint fk JOIN pg_class c ON c.oid=fk.conrelid
      JOIN pg_namespace n ON n.oid=c.relnamespace
      JOIN LATERAL unnest(fk.conkey) WITH ORDINALITY k(number,position) ON true
      JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.number
      WHERE fk.contype='f' AND n.nspname IN ('inventory','matching','findings','automation','dashboard','security','status','cve','system')
      AND NOT EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid=fk.conrelid AND i.indisvalid
       AND i.indpred IS NULL AND i.indexprs IS NULL AND
       ARRAY(SELECT number FROM unnest(i.indkey::smallint[]) WITH ORDINALITY x(number,position)
       WHERE position<=cardinality(fk.conkey) ORDER BY position)=fk.conkey)
      GROUP BY n.nspname,c.relname,fk.conname
    """).fetchall()
    for schema, table, constraint, columns in missing:
        suffix = hashlib.sha256((schema + "." + constraint).encode()).hexdigest()[:10]
        indexes.append(
            (
                schema,
                "purge_fk_" + table[:30] + "_" + suffix,
                schema + "." + table,
                "(" + columns + ")",
            )
        )
    # Keep the migration serialization lock across concurrent index transactions.
    driver.execute("SELECT pg_advisory_lock(2026030301)")
    try:
        with op.get_context().autocommit_block():
            timeout = driver.execute("SHOW statement_timeout").fetchone()[0]
            driver.execute("SET statement_timeout='0'")
            try:
                for schema, name, table, expression in indexes:
                    current = driver.execute(
                        "SELECT i.indisvalid FROM pg_index i WHERE i.indexrelid=to_regclass(%s)",
                        (schema + "." + name,),
                    ).fetchone()
                    if current and not current[0]:
                        driver.execute(
                            sql.SQL("DROP INDEX CONCURRENTLY {}.{}").format(
                                sql.Identifier(schema), sql.Identifier(name)
                            )
                        )
                    driver.execute(
                        sql.SQL("CREATE INDEX CONCURRENTLY IF NOT EXISTS {} ON {} {} ").format(
                            sql.Identifier(name),
                            sql.Identifier(*table.split(".")),
                            sql.SQL(expression),
                        )
                    )
            finally:
                driver.execute("SELECT set_config('statement_timeout',%s,false)", (timeout,))
    finally:
        driver.execute("SELECT pg_advisory_xact_lock(2026030301)")
        driver.execute("SELECT pg_advisory_unlock(2026030301)")
    driver.execute(PATCH, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Do not reintroduce blocking erasure scans")


SETUP = r"""
CREATE OR REPLACE FUNCTION inventory.erasure_refs(p_json jsonb[],p_text text[]) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog SET jit=off AS $$
 SELECT coalesce(array_agg(DISTINCT lower(value[1])),'{}'::text[])
 FROM regexp_matches(coalesce((SELECT string_agg(v::text,' ') FROM unnest(p_json) v),'')||' '||coalesce(array_to_string(p_text,' '),''),
 '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}','g') value
$$;
REVOKE ALL ON FUNCTION inventory.erasure_refs(jsonb[],text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION inventory.erasure_refs(jsonb[],text[]) TO api_reader,api_security,api_ingest,inventory_processor,importer,enricher,matcher,findings_writer,notification,event_dispatcher,status_probe,workflow_control,ansible_worker,dashboard_admin,reporter;
CREATE OR REPLACE FUNCTION inventory.erasure_expression(p_relation oid,p_alias text) RETURNS text
LANGUAGE sql STABLE SET search_path=pg_catalog AS $$
 SELECT 'inventory.erasure_refs(ARRAY['||coalesce(string_agg(
   CASE WHEN a.atttypid IN ('jsonb'::regtype,'json'::regtype) THEN
    CASE WHEN p_alias='' THEN quote_ident(a.attname) ELSE quote_ident(p_alias)||'.'||quote_ident(a.attname) END||'::jsonb' END,',' ORDER BY a.attnum),'')||']::jsonb[],ARRAY['||
 coalesce(string_agg(CASE WHEN a.atttypid IN ('uuid'::regtype,'text'::regtype,'varchar'::regtype,'bpchar'::regtype,'name'::regtype) THEN
    CASE WHEN p_alias='' THEN quote_ident(a.attname) ELSE quote_ident(p_alias)||'.'||quote_ident(a.attname) END||'::text' END,',' ORDER BY a.attnum),'')||']::text[])'
 FROM pg_attribute a WHERE a.attrelid=p_relation AND a.attnum>0 AND NOT a.attisdropped
$$;
REVOKE ALL ON FUNCTION inventory.erasure_expression(oid,text) FROM PUBLIC;
"""

PATCH = r"""
DO $$ DECLARE d text; old text; BEGIN
 SELECT pg_get_functiondef('inventory.erase_server(uuid,uuid)'::regprocedure) INTO d;
 d:=replace(d,'changed integer; erased integer:=0;','changed integer; erased integer:=0; finalized boolean:=false; lock_deadline timestamptz;');
 d:=replace(d,'PERFORM pg_advisory_xact_lock(7348001);PERFORM pg_advisory_xact_lock(909001);PERFORM pg_advisory_xact_lock(1010001);',
 'PERFORM pg_advisory_xact_lock(909002,hashtext(p_server::text));');
 old:='WITH candidate AS MATERIALIZED (SELECT %s::oid rel,inventory.purge_primary_key(%s,to_jsonb(row)) key,to_jsonb(row)::text document FROM %s row) INSERT INTO pg_temp.server_purge_rows SELECT rel,key FROM candidate WHERE EXISTS(SELECT 1 FROM pg_temp.server_purge_ids ids WHERE strpos(document,ids.id)>0) ON CONFLICT DO NOTHING';
 IF position(old IN d)=0 THEN RAISE EXCEPTION 'erasure reference patch mismatch'; END IF;
 d:=replace(d,old,'INSERT INTO pg_temp.server_purge_rows SELECT %s::oid,inventory.purge_primary_key(%s,to_jsonb(row)) FROM %s row WHERE %s && ARRAY(SELECT id FROM pg_temp.server_purge_ids) ON CONFLICT DO NOTHING');
 d:=replace(d,'rel.oid,rel.oid,rel.oid::regclass);','rel.oid,rel.oid,rel.oid::regclass,inventory.erasure_expression(rel.oid,''row''));');
 d:=replace(d,'''runtime_actions'',''notification_audit''','''runtime_actions'',''notification_audit'',''n8n_queue''');
 d:=replace(d,'  EXIT WHEN changed=0;',
 '  IF changed=0 THEN
    IF NOT finalized THEN
      lock_deadline:=clock_timestamp()+interval ''250 milliseconds'';
      WHILE NOT pg_try_advisory_xact_lock(7348001) LOOP
        IF clock_timestamp()>=lock_deadline THEN RAISE EXCEPTION ''erasure coordination busy'' USING ERRCODE=''55P03''; END IF;
        PERFORM pg_sleep(0.01);
      END LOOP;
      WHILE NOT pg_try_advisory_xact_lock(909001) LOOP
        IF clock_timestamp()>=lock_deadline THEN RAISE EXCEPTION ''erasure coordination busy'' USING ERRCODE=''55P03''; END IF;
        PERFORM pg_sleep(0.01);
      END LOOP;
      WHILE NOT pg_try_advisory_xact_lock(1010001) LOOP
        IF clock_timestamp()>=lock_deadline THEN RAISE EXCEPTION ''erasure coordination busy'' USING ERRCODE=''55P03''; END IF;
        PERFORM pg_sleep(0.01);
      END LOOP;
      IF NOT inventory.ansible_owner_active(p_actor) OR NOT EXISTS(SELECT 1 FROM inventory.servers s WHERE s.id=p_server AND (s.created_by=p_actor OR EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id WHERE ur.user_id=p_actor AND r.code=''admin''))) THEN RAISE EXCEPTION ''erasure requester unavailable'' USING ERRCODE=''42501''; END IF;
      finalized:=true;
    ELSE EXIT; END IF;
  END IF;');
 d:=replace(d,' FOR rel IN SELECT DISTINCT p.rel FROM pg_temp.server_purge_rows p ORDER BY p.rel LOOP',
 ' DROP TABLE IF EXISTS pg_temp.server_purge_orphans;
 CREATE TEMP TABLE server_purge_orphans(kind text,id text,PRIMARY KEY(kind,id)) ON COMMIT DROP;
 INSERT INTO pg_temp.server_purge_orphans SELECT DISTINCT ''workflow'',j.correlation_id::text FROM automation.jobs j
 JOIN pg_temp.server_purge_rows m ON m.rel=''automation.jobs''::regclass AND j.id=(m.key->>''id'')::uuid WHERE j.correlation_id IS NOT NULL ON CONFLICT DO NOTHING;
 INSERT INTO pg_temp.server_purge_orphans SELECT DISTINCT ''bill'',s.bill_digest FROM inventory.container_software s
 JOIN pg_temp.server_purge_rows m ON m.rel=''inventory.container_software''::regclass AND to_jsonb(s) @> m.key WHERE s.bill_digest IS NOT NULL ON CONFLICT DO NOTHING;
 FOR rel IN SELECT DISTINCT p.rel FROM pg_temp.server_purge_rows p ORDER BY p.rel LOOP');
 d:=replace(d,'DELETE FROM inventory.software_bills b WHERE NOT EXISTS',
 'DELETE FROM inventory.software_bills b WHERE b.digest IN (SELECT id::bytea FROM pg_temp.server_purge_orphans WHERE kind=''bill'') AND NOT EXISTS');
 d:=replace(d,'DELETE FROM automation.workflow_runs r WHERE NOT EXISTS',
 'DELETE FROM automation.workflow_runs r WHERE r.correlation_id IN (SELECT id::uuid FROM pg_temp.server_purge_orphans WHERE kind=''workflow'') AND NOT EXISTS');
 EXECUTE d;
END $$;
ALTER FUNCTION inventory.erase_server(uuid,uuid) SET jit='off';
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00060_transient_import_recovery','00061_scoped_server_erasure');
END $$;
"""
