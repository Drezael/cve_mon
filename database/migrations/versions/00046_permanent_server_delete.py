"""Explicit owner-scoped erasure, including immutable history and durable work references."""

from alembic import op

revision = "00046_permanent_server_delete"
down_revision = "00045_managed_ansible"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Deleted data cannot be restored into an active deployment")


DDL = r"""
-- Normal writes remain immutable. Only the narrowly granted definer operation may erase.
DO $$ DECLARE routine record; definition text; BEGIN
 FOR routine IN SELECT DISTINCT p.oid FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
 JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE NOT t.tgisinternal AND t.tgtype & 1=1 AND t.tgtype & 8=8
 AND n.nspname IN ('system','security','inventory','matching','findings','automation') LOOP
  SELECT pg_get_functiondef(routine.oid) INTO definition;
  definition:=regexp_replace(definition,'\mBEGIN\M',
   'BEGIN IF TG_OP=''DELETE'' AND current_user=''postgres_owner'' AND current_setting(''cve.server_purge'',true)=''on'' THEN RETURN OLD; END IF;', 'i');
  EXECUTE definition;
 END LOOP;
END $$;
-- Defer FK checks only inside the erasure transaction; regular commands still check immediately.
DO $$ DECLARE fk record; BEGIN
 FOR fk IN SELECT conrelid::regclass AS rel,conname FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace
 WHERE contype='f' AND NOT c.condeferrable AND n.nspname IN ('security','inventory','matching','findings','automation') LOOP
  EXECUTE format('ALTER TABLE %s ALTER CONSTRAINT %I DEFERRABLE INITIALLY IMMEDIATE',fk.rel,fk.conname);
 END LOOP;
END $$;
CREATE FUNCTION inventory.purge_primary_key(p_rel oid,p_row jsonb) RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_object_agg(a.attname,p_row->a.attname) FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid
 AND a.attnum=ANY(i.indkey) WHERE i.indrelid=p_rel AND i.indisprimary $$;
REVOKE ALL ON FUNCTION inventory.purge_primary_key(oid,jsonb) FROM PUBLIC;
CREATE FUNCTION inventory.erase_server(p_server uuid,p_actor uuid) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE fk record; rel record; digest record; member record; join_clause text; pk_join text; count_new integer; changed integer; erased integer:=0;
BEGIN
 IF session_user<>'dashboard_admin' OR NOT inventory.ansible_owner_active(p_actor)
 OR NOT EXISTS(SELECT 1 FROM inventory.servers s WHERE s.id=p_server AND (s.created_by=p_actor OR EXISTS(
 SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id WHERE ur.user_id=p_actor AND r.code='admin')))
 THEN RAISE EXCEPTION 'server erasure denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(909001);PERFORM pg_advisory_xact_lock(1010001);
 PERFORM 1 FROM inventory.servers WHERE id=p_server FOR UPDATE;
 PERFORM set_config('cve.server_purge','on',true);
 SET CONSTRAINTS ALL DEFERRED;
 DROP TABLE IF EXISTS pg_temp.server_purge_rows;
 DROP TABLE IF EXISTS pg_temp.server_purge_ids;
 CREATE TEMP TABLE server_purge_rows(rel oid NOT NULL,key jsonb NOT NULL,PRIMARY KEY(rel,key)) ON COMMIT DROP;
 CREATE TEMP TABLE server_purge_ids(id text PRIMARY KEY) ON COMMIT DROP;
 INSERT INTO pg_temp.server_purge_rows VALUES('inventory.servers'::regclass,jsonb_build_object('id',p_server));
 LOOP
  changed:=0;
  FOR fk IN SELECT c.conrelid,c.confrelid,c.conkey,c.confkey FROM pg_constraint c
   JOIN pg_namespace n ON n.oid=c.connamespace WHERE c.contype='f'
   AND n.nspname IN ('security','inventory','matching','findings','automation')
   AND EXISTS(SELECT 1 FROM pg_temp.server_purge_rows p WHERE p.rel=c.confrelid) LOOP
   SELECT string_agg(format('child.%I=parent.%I',ca.attname,pa.attname),' AND ') INTO join_clause
   FROM unnest(fk.conkey,fk.confkey) AS k(child,parent)
   JOIN pg_attribute ca ON ca.attrelid=fk.conrelid AND ca.attnum=k.child
   JOIN pg_attribute pa ON pa.attrelid=fk.confrelid AND pa.attnum=k.parent;
   EXECUTE format('INSERT INTO pg_temp.server_purge_rows SELECT %s,inventory.purge_primary_key(%s,to_jsonb(child)) FROM %s child JOIN %s parent ON %s JOIN pg_temp.server_purge_rows marked ON marked.rel=%s AND to_jsonb(parent) @> marked.key ON CONFLICT DO NOTHING',
    fk.conrelid,fk.conrelid,fk.conrelid::regclass,fk.confrelid::regclass,join_clause,fk.confrelid);
   GET DIAGNOSTICS count_new=ROW_COUNT;changed:=changed+count_new;
  END LOOP;
  -- A queued digest may include other servers. Preserve those members before erasing its aggregate.
  FOR digest IN SELECT DISTINCT parent.id,parent.status FROM automation.notification_intents child
   JOIN automation.notification_intents parent ON parent.id=child.digest_id
   JOIN pg_temp.server_purge_rows marked ON marked.rel='automation.notification_intents'::regclass
   AND to_jsonb(child) @> marked.key LOOP
   FOR member IN SELECT n.* FROM automation.notification_intents n WHERE n.digest_id=digest.id
    AND NOT EXISTS(SELECT 1 FROM pg_temp.server_purge_rows m
     WHERE m.rel='automation.notification_intents'::regclass AND to_jsonb(n) @> m.key) FOR UPDATE LOOP
    UPDATE automation.notification_intents SET digest_id=NULL,version=version+1,
     status=CASE WHEN digest.status IN ('relay_accepted','upstream_accepted','delivery_confirmed') THEN 'suppressed' ELSE status END
     WHERE id=member.id;
    INSERT INTO automation.notification_history(notification_id,version,old_status,new_status,reason,correlation_id)
     SELECT id,version,member.status,status,'digest_detached_after_erasure',correlation_id FROM automation.notification_intents WHERE id=member.id;
   END LOOP;
   INSERT INTO pg_temp.server_purge_rows VALUES('automation.notification_intents'::regclass,jsonb_build_object('id',digest.id)) ON CONFLICT DO NOTHING;
   GET DIAGNOSTICS count_new=ROW_COUNT;changed:=changed+count_new;
  END LOOP;
  INSERT INTO pg_temp.server_purge_ids SELECT DISTINCT v.value FROM pg_temp.server_purge_rows p CROSS JOIN LATERAL jsonb_each_text(p.key) v
  WHERE v.key IN ('id','server_id','snapshot_id','submission_id','inventory_id','run_id','result_id','finding_id','episode_id','event_id','job_id','notification_id','request_id','target_id')
  AND v.value ~ '^[a-f0-9]{8}-[a-f0-9-]{27}$' ON CONFLICT DO NOTHING;
  -- Soft queue/audit references do not have FKs but must not survive deletion.
  FOR rel IN SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE c.relkind='r' AND ((n.nspname='automation' AND c.relname IN ('jobs','event_outbox','runtime_actions','notification_audit'))
   OR (n.nspname='security' AND c.relname='audit_log')) LOOP
   EXECUTE format('INSERT INTO pg_temp.server_purge_rows SELECT %s,inventory.purge_primary_key(%s,to_jsonb(row)) FROM %s row WHERE EXISTS(SELECT 1 FROM pg_temp.server_purge_ids ids WHERE strpos(to_jsonb(row)::text,ids.id)>0) ON CONFLICT DO NOTHING',rel.oid,rel.oid,rel.oid::regclass);
   GET DIAGNOSTICS count_new=ROW_COUNT;changed:=changed+count_new;
  END LOOP;
  EXIT WHEN changed=0;
 END LOOP;
 DROP TABLE IF EXISTS pg_temp.server_purge_mail;
 CREATE TEMP TABLE server_purge_mail ON COMMIT DROP AS
 SELECT DISTINCT r.queue_id FROM automation.notification_delivery_results r JOIN automation.notification_delivery_attempts a ON a.id=r.attempt_id
 JOIN pg_temp.server_purge_rows marked ON marked.rel='automation.notification_delivery_attempts'::regclass AND to_jsonb(a) @> marked.key WHERE r.queue_id IS NOT NULL
 UNION SELECT DISTINCT e.queue_id FROM automation.notification_transport_evidence e JOIN pg_temp.server_purge_rows marked
 ON marked.rel='automation.notification_transport_evidence'::regclass AND to_jsonb(e) @> marked.key WHERE e.queue_id IS NOT NULL;
 DROP TABLE IF EXISTS pg_temp.server_purge_n8n;
 CREATE TEMP TABLE server_purge_n8n ON COMMIT DROP AS
 SELECT DISTINCT w.execution_id AS id FROM automation.workflow_requests w JOIN pg_temp.server_purge_rows marked
 ON marked.rel='automation.workflow_requests'::regclass AND to_jsonb(w) @> marked.key WHERE w.execution_id IS NOT NULL;
 FOR rel IN SELECT DISTINCT p.rel FROM pg_temp.server_purge_rows p ORDER BY p.rel LOOP
  EXECUTE format('DELETE FROM %s row USING pg_temp.server_purge_rows marked WHERE marked.rel=%s AND to_jsonb(row) @> marked.key',rel.rel::regclass,rel.rel);
  GET DIAGNOSTICS count_new=ROW_COUNT;erased:=erased+count_new;
 END LOOP;
 DELETE FROM inventory.software_bills b WHERE NOT EXISTS(SELECT 1 FROM inventory.container_software s WHERE s.bill_digest=b.digest);
 DELETE FROM automation.workflow_runs r WHERE NOT EXISTS(SELECT 1 FROM automation.workflow_requests w WHERE w.correlation_id=r.correlation_id);
 UPDATE inventory.acceptance_usage SET total_bytes=(SELECT coalesce(sum(payload_size),0) FROM inventory.submissions),total_count=(SELECT count(*) FROM inventory.submissions) WHERE singleton;
 UPDATE dashboard.order_versions SET version=version+1;
 SET CONSTRAINTS ALL IMMEDIATE;
 PERFORM set_config('cve.server_purge','off',true);
 GRANT SELECT ON pg_temp.server_purge_rows,pg_temp.server_purge_ids,pg_temp.server_purge_n8n,pg_temp.server_purge_mail TO dashboard_admin;
 RETURN erased;
END $$;
REVOKE ALL ON FUNCTION inventory.erase_server(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION inventory.erase_server(uuid,uuid) TO dashboard_admin;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00045_managed_ansible','00046_permanent_server_delete');
END $$;
"""
