"""Personal SSH vaults; legacy profiles must be explicitly reconfigured."""

from alembic import op

revision = "00075_personal_ansible_vault"
down_revision = "00074_manual_server_scan"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup; never downgrade credential protection")


DDL = r"""
CREATE TABLE security.ansible_vaults (
 user_id uuid PRIMARY KEY REFERENCES security.users(id),
 salt bytea NOT NULL CHECK(octet_length(salt)=16),
 password_envelope bytea NOT NULL CHECK(octet_length(password_envelope)=60),
 key_id text NOT NULL,
 runtime_envelope bytea NOT NULL CHECK(octet_length(runtime_envelope)=60),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON security.ansible_vaults FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON security.ansible_vaults TO api_security;
GRANT SELECT(user_id,key_id,runtime_envelope) ON security.ansible_vaults TO ansible_worker;
INSERT INTO security.audit_actions(action,writer_role) VALUES('auth.ansible_vault_changed','api_security');

-- Preserve old encrypted data for rollback, but invalidate all old runs and schedules.
UPDATE inventory.ansible_profiles SET enabled=false,version=version+1,updated_at=clock_timestamp();
CREATE FUNCTION inventory.require_ansible_vault() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF NEW.key_id='user-vault-v1' THEN
  IF NOT EXISTS(SELECT 1 FROM security.ansible_vaults WHERE user_id=NEW.owner_id)
  THEN RAISE EXCEPTION 'Personal vault required' USING ERRCODE='23514'; END IF;
 ELSIF NEW.enabled THEN
  RAISE EXCEPTION 'Vault credentials required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.owner_id IS DISTINCT FROM OLD.owner_id
 THEN RAISE EXCEPTION 'Vault ownership is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER require_ansible_vault BEFORE INSERT OR UPDATE ON inventory.ansible_profiles
FOR EACH ROW EXECUTE FUNCTION inventory.require_ansible_vault();
-- Profile writers need the existence check, without access to vault envelopes.
ALTER FUNCTION inventory.require_ansible_vault() SECURITY DEFINER;
REVOKE ALL ON FUNCTION inventory.require_ansible_vault() FROM PUBLIC;
DO $$ DECLARE definition text; routine text; BEGIN
 FOREACH routine IN ARRAY ARRAY['inventory.schedule_ansible(uuid,text,uuid)',
                               'inventory.managed_ansible_tick()'] LOOP
  SELECT pg_get_functiondef(routine::regprocedure) INTO definition;
  IF (length(definition)-length(replace(definition,
      'AND inventory.ansible_owner_active(p.owner_id)','')))
      /length('AND inventory.ansible_owner_active(p.owner_id)') <> 1
  THEN RAISE EXCEPTION 'Vault schedule patch mismatch'; END IF;
  EXECUTE replace(definition,'AND inventory.ansible_owner_active(p.owner_id)',
   'AND p.key_id=''user-vault-v1'' AND inventory.ansible_owner_active(p.owner_id)');
 END LOOP;
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 IF strpos(definition,'00074_manual_server_scan')=0
 THEN RAISE EXCEPTION 'Vault status patch mismatch'; END IF;
 EXECUTE replace(definition,'00074_manual_server_scan','00075_personal_ansible_vault');
END $$;
"""
