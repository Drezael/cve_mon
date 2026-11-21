"""Use indexed cleanup projections and enforce a database deadline for coordination."""

from alembic import op

revision = "00063_bounded_server_erasure"
down_revision = "00062_inventory_server_metadata"
branch_labels = None
depends_on = None

REPLACEMENTS = (
    ("to_jsonb(child) @> marked.key", "child.id=(marked.key->>'id')::uuid"),
    ("to_jsonb(n) @> m.key", "n.id=(m.key->>'id')::uuid"),
    ("to_jsonb(a) @> marked.key", "a.id=(marked.key->>'id')::uuid"),
    ("to_jsonb(e) @> marked.key", "e.id=(marked.key->>'id')::uuid"),
    ("to_jsonb(w) @> marked.key", "w.job_id=(marked.key->>'job_id')::uuid"),
    ("to_jsonb(q) @> marked.key", "q.id=(marked.key->>'id')::uuid"),
    (
        "to_jsonb(s) @> m.key",
        "s.snapshot_id=(m.key->>'snapshot_id')::uuid "
        "AND s.record_number=(m.key->>'record_number')::integer",
    ),
    ("WHERE id=p_server FOR UPDATE;", "WHERE id=p_server;"),
    (
        "      lock_deadline:=clock_timestamp()+interval '250 milliseconds';",
        "      PERFORM set_config('transaction_timeout','750ms',true);\n"
        "      lock_deadline:=clock_timestamp()+interval '100 milliseconds';",
    ),
)


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    definition = driver.execute(
        "SELECT pg_get_functiondef('inventory.erase_server(uuid,uuid)'::regprocedure)"
    ).fetchone()[0]
    for before, after in REPLACEMENTS:
        if before not in definition:
            raise RuntimeError("Erasure projection patch mismatch")
        definition = definition.replace(before, after)
    start = definition.index("      WHILE NOT pg_try_advisory_xact_lock(909001)")
    end = definition.index("      IF NOT inventory.ansible_owner_active", start)
    definition = definition[:start] + definition[end:]
    definition = definition.replace(
        "finalized boolean:=false;",
        "finalized boolean:=false; expected_version bigint:=nullif(current_setting('cve.erasure_expected_version',true),'')::bigint;",
    )
    definition = definition.replace(
        "      IF NOT inventory.ansible_owner_active",
        "      PERFORM 1 FROM inventory.servers WHERE id=p_server FOR UPDATE;\n"
        "      IF expected_version IS NOT NULL AND NOT EXISTS(SELECT 1 FROM inventory.servers WHERE id=p_server AND version=expected_version) THEN RAISE EXCEPTION 'server version changed' USING ERRCODE='40001'; END IF;\n"
        "      IF NOT inventory.ansible_owner_active",
    )
    driver.execute(definition, prepare=False)
    driver.execute("ALTER FUNCTION inventory.erase_server(uuid,uuid) SET lock_timeout='100ms'")
    driver.execute(
        r"""
    DO $$ DECLARE definition text; BEGIN
      SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
      EXECUTE replace(definition,'00062_inventory_server_metadata','00063_bounded_server_erasure');
    END $$;
    """,
        prepare=False,
    )


def downgrade() -> None:
    raise RuntimeError("Do not restore unbounded global erasure locks")
