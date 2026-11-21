"""Resume full inventory matching when a previously removed server returns to monitoring."""

from alembic import op

revision = "00042_server_scan_lifecycle"
down_revision = "00041_server_discovery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Use the verified backup; preserve server and finding history")


DDL = r"""
UPDATE automation.job_types SET producer_roles=array_append(producer_roles,'dashboard_admin'::name)
 WHERE code='matching.evaluate_snapshot' AND NOT 'dashboard_admin'::name=ANY(producer_roles);
CREATE FUNCTION matching.server_restored() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog AS $$
DECLARE snapshot uuid;
BEGIN
 IF session_user='dashboard_admin' AND NEW.status='active' AND OLD.status<>'active' THEN
  SELECT snapshot_id INTO snapshot FROM inventory.server_current_snapshots WHERE server_id=NEW.id;
  IF snapshot IS NOT NULL THEN
   PERFORM automation.enqueue_job('matching.evaluate_snapshot',1,jsonb_build_object('snapshot_id',snapshot),
    'server-restored:'||NEW.id::text||':'||NEW.version::text,gen_random_uuid(),0,NULL,NULL,3,'server-restored',false);
  END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION matching.server_restored() FROM PUBLIC;
CREATE TRIGGER restored_server_scan AFTER UPDATE OF status ON inventory.servers
 FOR EACH ROW WHEN(OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION matching.server_restored();
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00041_server_discovery','00042_server_scan_lifecycle');
END $$;
"""
