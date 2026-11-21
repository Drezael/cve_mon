"""foundation — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
CREATE SCHEMA cve; CREATE SCHEMA inventory; CREATE SCHEMA matching; CREATE SCHEMA findings;
CREATE SCHEMA security; CREATE SCHEMA automation; CREATE SCHEMA system; CREATE SCHEMA dashboard;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres_owner REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres_owner REVOKE ALL ON SEQUENCES FROM PUBLIC;
CREATE FUNCTION system.version_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.id <> OLD.id OR NEW.created_at <> OLD.created_at THEN RAISE EXCEPTION 'immutable identity'; END IF;
 IF NEW.version <> OLD.version+1 THEN RAISE EXCEPTION 'version must increase by one' USING ERRCODE='40001'; END IF;
 NEW.updated_at := clock_timestamp(); RETURN NEW;
END $$;
CREATE FUNCTION system.append_only() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'append-only record' USING ERRCODE='42501'; END $$;
CREATE FUNCTION system.has_reserved_key(value jsonb, keys text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT CASE jsonb_typeof(value)
 WHEN 'object' THEN EXISTS(SELECT 1 FROM jsonb_each(value) e WHERE lower(e.key)=ANY(keys) OR system.has_reserved_key(e.value,keys))
 WHEN 'array' THEN EXISTS(SELECT 1 FROM jsonb_array_elements(value) e WHERE system.has_reserved_key(e,keys))
 ELSE false END
$$;
CREATE FUNCTION system.safe_metadata(value jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT octet_length(value::text)<=65536 AND NOT system.has_reserved_key(value,
 ARRAY['password','password_hash','authorization','cookie','token','api_token','session_token','secret','totp_secret','recovery_code','private_key'])
$$;
"""
