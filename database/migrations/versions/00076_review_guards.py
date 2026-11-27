"""Audit vocabulary and verify previously installed safety patches on upgrade."""

from alembic import op

revision = "00076_review_guards"
down_revision = "00075_personal_ansible_vault"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup rather than remove safety guards")


DDL = r"""
DO $$ DECLARE definition text; routine text; BEGIN
 FOREACH routine IN ARRAY ARRAY['inventory.schedule_ansible(uuid,text,uuid)',
                               'inventory.managed_ansible_tick()'] LOOP
  SELECT pg_get_functiondef(routine::regprocedure) INTO definition;
  IF strpos(definition,$guard$p.key_id='user-vault-v1'$guard$)=0
  THEN RAISE EXCEPTION 'Required vault schedule guard absent'; END IF;
 END LOOP;
 SELECT pg_get_functiondef('inventory.erase_server(uuid,uuid)'::regprocedure) INTO definition;
 IF strpos(definition,'expected_version')=0 OR strpos(definition,'transaction_timeout')=0
    OR strpos(definition,'to_jsonb(child) @> marked.key')>0
 THEN RAISE EXCEPTION 'Required erasure safety guard absent'; END IF;
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 IF strpos(definition,'00075_personal_ansible_vault')=0
 THEN RAISE EXCEPTION 'Review status patch mismatch'; END IF;
 EXECUTE replace(definition,'00075_personal_ansible_vault','00076_review_guards');
END $$;
CREATE OR REPLACE VIEW matching.current_evaluations AS
 SELECT c.current_version,r.*,
 (s.snapshot_id=r.snapshot_id AND e.current_revision_id=r.enrichment_revision_id
  AND a.status='active' AND r.rule_version='matching-2') AS is_current
 FROM matching.current_results c JOIN matching.result_revisions r ON r.id=c.result_id
 JOIN inventory.servers a ON a.id=r.server_id
 LEFT JOIN inventory.server_current_snapshots s ON s.server_id=r.server_id
 JOIN cve.enrichment_identities e ON e.identity=r.identity;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('matching.metrics()'::regprocedure) INTO definition;
 IF strpos(definition,'matching-1')=0 THEN RAISE EXCEPTION 'Matching metrics patch mismatch'; END IF;
 EXECUTE replace(definition,'matching-1','matching-2');
END $$;
INSERT INTO matching.rule_versions VALUES
 ('matching-2','{"debian":"dpkg-1","rpm":"rpm-1","semver":"semver-2"}',clock_timestamp());
INSERT INTO security.audit_actions(action,writer_role) VALUES
 ('ansible.configured','api_security'),('ansible.host_key_confirmed','api_security');
"""
