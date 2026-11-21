"""identities — explizite PostgreSQL-DDL, Phase 3."""

from alembic import op

revision = "0005_identities"
down_revision = "0004_vulnerabilities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    driver = op.get_bind().connection.driver_connection
    assert driver is not None
    driver.execute(DDL, prepare=False)


def downgrade() -> None:
    raise RuntimeError("Datenhaltende Rückkehr ausschließlich über geprüften Backup/Restore")


DDL = r"""
CREATE TABLE security.users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), username text NOT NULL CHECK(btrim(username)<>''),
 username_normalized text GENERATED ALWAYS AS (casefold(normalize(btrim(username),NFKC))) STORED UNIQUE,
 email text NOT NULL CHECK(email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'),
 email_normalized text GENERATED ALWAYS AS (casefold(normalize(btrim(email),NFKC))) STORED UNIQUE,
 display_name text NOT NULL, status text NOT NULL DEFAULT 'pending_activation' CHECK(status IN ('pending_activation','active','locked','disabled','archived')),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), last_login_at timestamptz,
 version bigint NOT NULL DEFAULT 1 CHECK(version>0)
);
CREATE TRIGGER users_version BEFORE UPDATE ON security.users FOR EACH ROW EXECUTE FUNCTION system.version_guard();
CREATE TABLE security.password_credentials (
 user_id uuid PRIMARY KEY REFERENCES security.users(id), password_hash text NOT NULL
 CHECK(password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]{16,}\$[A-Za-z0-9+/]{32,}$'),
 changed_at timestamptz NOT NULL DEFAULT now(), algorithm text NOT NULL DEFAULT 'argon2id' CHECK(algorithm='argon2id'),
 must_change boolean NOT NULL DEFAULT false
);
CREATE TABLE security.roles (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), code text NOT NULL UNIQUE, name text NOT NULL,
 is_system boolean NOT NULL DEFAULT false, description text, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE security.permissions (code text PRIMARY KEY, description text NOT NULL);
CREATE TABLE security.role_permissions (
 role_id uuid NOT NULL REFERENCES security.roles(id), permission_code text NOT NULL REFERENCES security.permissions(code), PRIMARY KEY(role_id,permission_code)
);
CREATE TABLE security.user_roles (
 user_id uuid NOT NULL REFERENCES security.users(id), role_id uuid NOT NULL REFERENCES security.roles(id),
 granted_at timestamptz NOT NULL DEFAULT now(), granted_by uuid REFERENCES security.users(id), PRIMARY KEY(user_id,role_id)
);
CREATE TABLE security.user_server_access (
 user_id uuid NOT NULL REFERENCES security.users(id), server_id uuid NOT NULL REFERENCES inventory.servers(id),
 can_read boolean NOT NULL DEFAULT true, can_upload boolean NOT NULL DEFAULT false, granted_by uuid REFERENCES security.users(id),
 PRIMARY KEY(user_id,server_id), CHECK(NOT can_upload OR can_read)
);
CREATE TABLE security.user_group_access (
 user_id uuid NOT NULL REFERENCES security.users(id), group_id uuid NOT NULL REFERENCES inventory.server_groups(id),
 can_read boolean NOT NULL DEFAULT true, granted_by uuid REFERENCES security.users(id), PRIMARY KEY(user_id,group_id)
);
CREATE TABLE security.sessions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES security.users(id),
 verifier bytea NOT NULL UNIQUE CHECK(octet_length(verifier)=32), created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL, revoked_at timestamptz, mfa_verified_at timestamptz,
 CHECK(expires_at>created_at), CHECK(revoked_at IS NULL OR revoked_at>=created_at)
);
CREATE TABLE security.mfa_methods (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES security.users(id),
 kind text NOT NULL CHECK(kind='totp'), ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)>=32), key_id text NOT NULL CHECK(key_id<>''),
 created_at timestamptz NOT NULL DEFAULT now(), verified_at timestamptz, revoked_at timestamptz
);
CREATE TABLE security.recovery_codes (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES security.users(id),
 verifier bytea NOT NULL UNIQUE CHECK(octet_length(verifier)=32), created_at timestamptz NOT NULL DEFAULT now(), used_at timestamptz
);
CREATE TABLE security.account_tokens (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES security.users(id),
 purpose text NOT NULL CHECK(purpose IN ('activation','password_reset','email_change','mfa_reset')),
 verifier bytea NOT NULL UNIQUE CHECK(octet_length(verifier)=32), created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL, used_at timestamptz, revoked_at timestamptz, CHECK(expires_at>created_at)
);
CREATE TABLE security.technical_principals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL UNIQUE, status text NOT NULL CHECK(status IN ('active','disabled')),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE security.api_tokens (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), principal_id uuid NOT NULL REFERENCES security.technical_principals(id),
 verifier bytea NOT NULL UNIQUE CHECK(octet_length(verifier)=32), created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL, revoked_at timestamptz, CHECK(expires_at>created_at)
);
CREATE TABLE security.principal_server_access (
 principal_id uuid NOT NULL REFERENCES security.technical_principals(id), server_id uuid NOT NULL REFERENCES inventory.servers(id),
 PRIMARY KEY(principal_id,server_id)
);
ALTER TABLE inventory.upload_receipts ADD FOREIGN KEY(actor_user_id) REFERENCES security.users(id);
ALTER TABLE inventory.upload_receipts ADD FOREIGN KEY(technical_principal_id) REFERENCES security.technical_principals(id);
ALTER TABLE findings.status_history ADD FOREIGN KEY(actor_user_id) REFERENCES security.users(id);
CREATE VIEW security.user_directory AS SELECT id,username,display_name,status,created_at,updated_at,version FROM security.users;
CREATE VIEW security.effective_server_access AS
 SELECT user_id,server_id,bool_or(can_read) AS can_read,bool_or(can_upload) AS can_upload FROM (
 SELECT user_id,server_id,can_read,can_upload FROM security.user_server_access
 UNION ALL SELECT a.user_id,m.server_id,a.can_read,false FROM security.user_group_access a
 JOIN inventory.server_group_memberships m ON m.group_id=a.group_id) grants GROUP BY user_id,server_id;
CREATE INDEX sessions_user ON security.sessions(user_id,expires_at) WHERE revoked_at IS NULL;
CREATE INDEX tokens_principal ON security.api_tokens(principal_id) WHERE revoked_at IS NULL;
"""
