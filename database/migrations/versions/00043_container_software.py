"""Deduplicated software inventories and snapshot-bound container scan evidence."""

from alembic import op

revision = "00043_container_software"
down_revision = "00042_server_scan_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Restore the verified backup; retain container inventory evidence")


DDL = r"""
ALTER TABLE inventory.submissions DROP CONSTRAINT submissions_schema_version_check;
ALTER TABLE inventory.submissions ADD CONSTRAINT submissions_schema_version_check CHECK(schema_version IN ('1.0','1.1','1.2','1.3'));
ALTER TABLE inventory.snapshots DROP CONSTRAINT snapshots_schema_version_check;
ALTER TABLE inventory.snapshots ADD CONSTRAINT snapshots_schema_version_check CHECK(schema_version IN ('1.0','1.1','1.2','1.3'));
DO $$ DECLARE c record; definition text; BEGIN
 FOR c IN SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint
 WHERE conrelid='inventory.submissions'::regclass AND contype='c'
 AND pg_get_constraintdef(oid) LIKE '%CASE%payload_json%host%' LOOP
  EXECUTE format('ALTER TABLE inventory.submissions DROP CONSTRAINT %I',c.conname);
 END LOOP;
 SELECT pg_get_functiondef('inventory.accept_submission()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'NEW.schema_version=''1.2''','(NEW.schema_version IN (''1.2'',''1.3'') AND NEW.payload_json ? ''host'')');
 SELECT pg_get_functiondef('inventory.require_complete_sections()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'s.schema_version IN (''1.1'',''1.2'')','s.schema_version IN (''1.1'',''1.2'',''1.3'')');
END $$;
ALTER TABLE inventory.submissions ADD CHECK(CASE WHEN payload_json ? 'host' THEN
 schema_version IN ('1.2','1.3') AND NOT payload_json ? 'server_id'
 ELSE payload_json->>'server_id'=server_id::text END);
ALTER TABLE inventory.snapshots DROP CONSTRAINT original_identity_matches;
ALTER TABLE inventory.snapshots ADD CONSTRAINT original_identity_matches CHECK(coalesce(
 original_json->>'inventory_id'=inventory_id::text AND CASE WHEN original_json ? 'host'
 THEN schema_version IN ('1.2','1.3') AND original_json->'host'->>'monitoring_id' IS NOT NULL
 AND NOT original_json ? 'server_id' ELSE original_json->>'server_id'=server_id::text END,false));
GRANT SELECT ON inventory.containers,inventory.server_current_snapshots,inventory.snapshots TO api_security;
CREATE TABLE inventory.software_bills (
 digest bytea PRIMARY KEY CHECK(octet_length(digest)=32),document jsonb NOT NULL,
 package_count integer NOT NULL CHECK(package_count BETWEEN 0 AND 20000)
);
CREATE TABLE inventory.container_software (
 snapshot_id uuid NOT NULL REFERENCES inventory.snapshots(id),record_number integer NOT NULL,
 container_id text NOT NULL,image_id text NOT NULL,scope text NOT NULL CHECK(scope IN ('image','runtime','mount')),
 target text,status text NOT NULL CHECK(status IN ('complete','partial','failed','not_collected')),
 captured_at timestamptz NOT NULL,error_code text,bill_digest bytea REFERENCES inventory.software_bills(digest),
 PRIMARY KEY(snapshot_id,record_number),
 CHECK(status NOT IN ('complete','partial') OR bill_digest IS NOT NULL)
);
CREATE INDEX container_software_lookup ON inventory.container_software(snapshot_id,container_id);
GRANT SELECT,INSERT ON inventory.software_bills,inventory.container_software TO inventory_processor;
GRANT SELECT ON inventory.software_bills,inventory.container_software TO matcher,api_reader,api_security,reporter;
GRANT USAGE ON SCHEMA inventory TO workflow_control;
CREATE TABLE inventory.collection_targets (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),principal_id uuid NOT NULL REFERENCES security.technical_principals(id),
 server_id uuid REFERENCES inventory.servers(id),alias text NOT NULL CHECK(alias ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'),enabled boolean NOT NULL DEFAULT true,
 interval_seconds integer NOT NULL DEFAULT 21600 CHECK(interval_seconds BETWEEN 300 AND 604800),
 next_due timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(principal_id,alias)
);
CREATE TABLE inventory.collection_requests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),target_id uuid NOT NULL REFERENCES inventory.collection_targets(id),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','running','succeeded','failed')),
 execution_id text NOT NULL,workflow_id text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 attempts integer NOT NULL DEFAULT 0,lease_until timestamptz,lease_token uuid,submission_id uuid REFERENCES inventory.submissions(id),
 error_code text
);
CREATE INDEX collection_pending ON inventory.collection_requests(target_id,state);
CREATE FUNCTION inventory.collection_tick(p_execution text,p_workflow text) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog AS $$ DECLARE target record; n integer:=0; BEGIN
 IF session_user<>'workflow_control' OR p_workflow<>'cve-control-inventory' THEN RAISE EXCEPTION 'collection tick denied' USING ERRCODE='42501'; END IF;
 UPDATE inventory.collection_requests SET state=CASE WHEN attempts<3 THEN 'pending' ELSE 'failed' END,
 lease_token=NULL,error_code='lease_expired' WHERE state='running' AND lease_until<clock_timestamp();
 FOR target IN SELECT t.* FROM inventory.collection_targets t WHERE t.enabled AND t.next_due<=clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM inventory.collection_requests r WHERE r.target_id=t.id AND r.state IN ('pending','running'))
 AND security.collector_actor(t.principal_id) IS NOT NULL
 AND (t.server_id IS NULL OR security.collector_can_upload(t.principal_id,t.server_id)) FOR UPDATE SKIP LOCKED LOOP
  INSERT INTO inventory.collection_requests(target_id,execution_id,workflow_id) VALUES(target.id,p_execution,p_workflow);
  UPDATE inventory.collection_targets SET next_due=clock_timestamp()+make_interval(secs=>interval_seconds) WHERE id=target.id;
  n:=n+1;
 END LOOP;
 RETURN n;
END $$;
REVOKE ALL ON FUNCTION inventory.collection_tick(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION inventory.collection_tick(text,text) TO workflow_control;
CREATE FUNCTION inventory.collection_register(p_principal uuid,p_alias text,p_interval integer,p_enabled boolean,p_now boolean)
 RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE target uuid; BEGIN
 IF session_user<>'api_ingest' OR security.collector_actor(p_principal) IS NULL THEN RAISE EXCEPTION 'collector required' USING ERRCODE='42501'; END IF;
 INSERT INTO inventory.collection_targets(principal_id,alias,interval_seconds,enabled) VALUES(p_principal,p_alias,p_interval,p_enabled)
 ON CONFLICT(principal_id,alias) DO UPDATE SET interval_seconds=p_interval,enabled=p_enabled,
 next_due=CASE WHEN p_now THEN clock_timestamp() ELSE collection_targets.next_due END RETURNING id INTO target;
 RETURN target;
END $$;
CREATE FUNCTION inventory.collection_claim(p_principal uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog AS $$ DECLARE request inventory.collection_requests; alias text; BEGIN
 IF session_user<>'api_ingest' OR security.collector_actor(p_principal) IS NULL THEN RAISE EXCEPTION 'collector required' USING ERRCODE='42501'; END IF;
 SELECT r.* INTO request FROM inventory.collection_requests r JOIN inventory.collection_targets t ON t.id=r.target_id
 WHERE t.principal_id=p_principal AND t.enabled AND r.state='pending' AND r.attempts<3 ORDER BY r.created_at
 FOR UPDATE OF r SKIP LOCKED LIMIT 1;
 IF request.id IS NULL THEN RETURN NULL; END IF;
 UPDATE inventory.collection_requests SET state='running',attempts=attempts+1,lease_until=clock_timestamp()+interval '45 minutes',
 lease_token=gen_random_uuid() WHERE id=request.id RETURNING * INTO request;
 SELECT t.alias INTO alias FROM inventory.collection_targets t WHERE t.id=request.target_id;
 RETURN jsonb_build_object('request_id',request.id,'alias',alias,'lease_token',request.lease_token,
 'execution_id',request.execution_id,'workflow_id',request.workflow_id);
END $$;
CREATE FUNCTION inventory.collection_finish(p_principal uuid,p_request uuid,p_token uuid,p_submission uuid)
 RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF session_user<>'api_ingest' OR security.collector_actor(p_principal) IS NULL THEN RAISE EXCEPTION 'collector required' USING ERRCODE='42501'; END IF;
 IF p_submission IS NOT NULL AND NOT EXISTS(SELECT 1 FROM inventory.submissions WHERE id=p_submission
 AND technical_principal_id=p_principal AND received_at>=(SELECT created_at FROM inventory.collection_requests WHERE id=p_request)) THEN RAISE EXCEPTION 'submission owner mismatch' USING ERRCODE='42501'; END IF;
 UPDATE inventory.collection_requests r SET state=CASE WHEN p_submission IS NOT NULL THEN 'succeeded' ELSE 'failed' END,
 submission_id=p_submission,error_code=CASE WHEN p_submission IS NULL THEN 'collection_failed' END,lease_token=NULL
 FROM inventory.collection_targets t WHERE t.id=r.target_id AND t.principal_id=p_principal
 AND r.id=p_request AND r.state='running' AND r.lease_token=p_token AND r.lease_until>clock_timestamp();
 IF NOT FOUND THEN RETURN false; END IF;
 IF p_submission IS NOT NULL THEN
 UPDATE inventory.collection_targets t SET server_id=s.server_id FROM inventory.submissions s,inventory.collection_requests r
 WHERE r.id=p_request AND r.target_id=t.id AND s.id=p_submission;
 END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION inventory.collection_register(uuid,text,integer,boolean,boolean),inventory.collection_claim(uuid),
 inventory.collection_finish(uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION inventory.collection_register(uuid,text,integer,boolean,boolean),inventory.collection_claim(uuid),
 inventory.collection_finish(uuid,uuid,uuid,uuid) TO api_ingest;
GRANT SELECT ON inventory.collection_targets,inventory.collection_requests TO api_security,reporter;
GRANT EXECUTE ON FUNCTION security.collector_actor(uuid) TO workflow_control;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('automation.workflow_tick(text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'''import'',''status'',''findings'',''notifications''','''import'',''inventory'',''status'',''findings'',''notifications''');
 definition:=replace(definition,' IF p_stage=''import'' THEN',
 ' IF p_stage=''inventory'' THEN
 RETURN jsonb_build_object(''scheduled'',inventory.collection_tick(p_execution,p_workflow));
 ELSIF p_stage=''import'' THEN');
 EXECUTE definition;
END $$;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00042_server_scan_lifecycle','00043_container_software');
END $$;
"""
