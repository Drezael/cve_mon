"""Durable manual full inventory scans enter the existing n8n dispatch queue."""

from alembic import op

revision = "00074_manual_server_scan"
down_revision = "00073_dashboard_shares"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve queued server scans")


DDL = r"""
UPDATE automation.job_types SET producer_roles=array_append(producer_roles,'api_security'::name)
WHERE code='matching.evaluate_snapshot' AND NOT 'api_security'::name=ANY(producer_roles);
CREATE FUNCTION inventory.request_full_scan(p_actor uuid,p_server uuid,p_key uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE snapshot uuid; job uuid; BEGIN
 IF session_user<>'api_security' OR NOT EXISTS(
 SELECT 1 FROM security.users u JOIN inventory.servers s ON s.id=p_server
 WHERE u.id=p_actor AND u.status='active' AND s.status='active' AND
 (s.created_by=u.id OR EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r ON r.id=ur.role_id WHERE ur.user_id=u.id AND r.code='admin'))
 AND EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.role_permissions rp ON rp.role_id=ur.role_id WHERE ur.user_id=u.id AND rp.permission_code='server:inventory:manage')
 ) THEN RAISE EXCEPTION 'Server scan denied' USING ERRCODE='42501'; END IF;
 SELECT snapshot_id INTO snapshot FROM inventory.server_current_snapshots WHERE server_id=p_server;
 IF snapshot IS NULL THEN RAISE EXCEPTION 'No current inventory' USING ERRCODE='22023'; END IF;
 SELECT id INTO job FROM automation.enqueue_job('matching.evaluate_snapshot',1,jsonb_build_object('snapshot_id',snapshot),
 'manual-scan:'||p_server::text||':'||p_key::text,p_key,0,NULL,NULL,3,'manual-server-scan',false);
 RETURN jsonb_build_object('job_id',job,'snapshot_id',snapshot,'state','queued');
END $$;
REVOKE ALL ON FUNCTION inventory.request_full_scan(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION inventory.request_full_scan(uuid,uuid,uuid) TO api_security;
INSERT INTO security.audit_actions(action,writer_role) VALUES('inventory.full_scan_requested','api_security');
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00073_dashboard_shares','00074_manual_server_scan');
END $$;
"""
