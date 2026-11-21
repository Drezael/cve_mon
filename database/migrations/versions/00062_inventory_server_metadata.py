"""Apply owner-edited server metadata atomically with inventory acceptance."""

from alembic import op

revision = "00062_inventory_server_metadata"
down_revision = "00061_scoped_server_erasure"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(SQL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve inventory metadata idempotency history")


SQL = r"""
CREATE TABLE inventory.submission_metadata(
 submission_id uuid PRIMARY KEY REFERENCES inventory.submissions(id) ON DELETE CASCADE,
 metadata jsonb NOT NULL CHECK(jsonb_typeof(metadata)='object')
);
REVOKE ALL ON inventory.submission_metadata FROM PUBLIC;
CREATE FUNCTION inventory.apply_upload_metadata(p_submission uuid,p_actor uuid,p_metadata jsonb,p_duplicate boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target inventory.servers%ROWTYPE; existing jsonb; sid uuid;
BEGIN
 IF session_user<>'api_security' OR jsonb_typeof(p_metadata) IS DISTINCT FROM 'object'
 OR NOT (p_metadata ?& ARRAY['display_name','description','environment','criticality','exposure'])
 OR p_metadata-ARRAY['display_name','description','environment','criticality','exposure']<>'{}'::jsonb
 OR jsonb_typeof(p_metadata->'display_name') IS DISTINCT FROM 'string'
 OR length(p_metadata->>'display_name') NOT BETWEEN 1 AND 128
 OR length(coalesce(p_metadata->>'description',''))>2000
 OR length(coalesce(p_metadata->>'environment',''))>64
 OR coalesce(p_metadata->>'criticality','') NOT IN ('low','medium','high','critical')
 OR coalesce(p_metadata->>'exposure','') NOT IN ('unknown','internal','restricted','internet_exposed')
 OR NOT inventory.ansible_owner_active(p_actor)
 THEN RAISE EXCEPTION 'invalid metadata request' USING ERRCODE='42501'; END IF;
 SELECT server_id INTO sid FROM inventory.submissions
 WHERE id=p_submission AND source='dashboard_file' AND actor_user_id=p_actor;
 IF sid IS NULL THEN RAISE EXCEPTION 'submission unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO target FROM inventory.servers WHERE id=sid FOR UPDATE;
 IF target.status IS DISTINCT FROM 'active' OR (target.created_by IS DISTINCT FROM p_actor AND NOT EXISTS(
 SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id
 WHERE ur.user_id=p_actor AND r.code='admin'))
 THEN RAISE EXCEPTION 'metadata owner required' USING ERRCODE='42501'; END IF;
 SELECT metadata INTO existing FROM inventory.submission_metadata WHERE submission_id=p_submission;
 IF existing IS NOT NULL THEN
  IF existing<>p_metadata THEN RAISE EXCEPTION 'metadata conflict' USING ERRCODE='23505'; END IF;
  RETURN;
 END IF;
 IF p_duplicate THEN RAISE EXCEPTION 'metadata conflict' USING ERRCODE='23505'; END IF;
 INSERT INTO inventory.submission_metadata VALUES(p_submission,p_metadata);
 UPDATE inventory.servers SET display_name=p_metadata->>'display_name',description=p_metadata->>'description',
 environment=p_metadata->>'environment',criticality=p_metadata->>'criticality',exposure=p_metadata->>'exposure',
 updated_by=p_actor,updated_at=clock_timestamp(),version=version+1 WHERE id=sid;
 INSERT INTO security.audit_log(action,actor_user_id,object_type,object_id,request_id,outcome,metadata)
 VALUES('server_metadata_from_inventory',p_actor,'server',sid::text,gen_random_uuid(),'success',jsonb_build_object('submission_id',p_submission));
END $$;
REVOKE ALL ON FUNCTION inventory.apply_upload_metadata(uuid,uuid,jsonb,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION inventory.apply_upload_metadata(uuid,uuid,jsonb,boolean) TO api_security;
DO $$ DECLARE d text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO d;
 EXECUTE replace(d,'00061_scoped_server_erasure','00062_inventory_server_metadata');
END $$;
"""
