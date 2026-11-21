"""Persistent account-owned YAML dashboards with optimistic revisions."""

from alembic import op

revision = "00072_custom_dashboards"
down_revision = "00071_personal_server_groups"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Preserve saved dashboards")


DDL = r"""
CREATE TABLE dashboard.custom_dashboards(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 owner_id uuid NOT NULL REFERENCES security.users(id) ON DELETE CASCADE,
 title text NOT NULL CHECK(length(btrim(title)) BETWEEN 1 AND 128),
 yaml_source text NOT NULL CHECK(octet_length(yaml_source)<=32768),
 configuration jsonb NOT NULL CHECK(jsonb_typeof(configuration)='object'),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX custom_dashboards_owner_title ON dashboard.custom_dashboards(owner_id,casefold(normalize(btrim(title),NFKC)));
REVOKE ALL ON dashboard.custom_dashboards FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON dashboard.custom_dashboards TO api_security;
INSERT INTO security.audit_actions(action,writer_role)
SELECT 'custom_dashboard.'||action,'api_security' FROM unnest(ARRAY['created','updated','deleted']) action;
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('status.sample_v49()'::regprocedure) INTO definition;
 EXECUTE replace(definition,'00071_personal_server_groups','00072_custom_dashboards');
END $$;
"""
