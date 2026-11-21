#!/usr/bin/env bash
set -euo pipefail
# Ausschließlich Erstinitialisierung eines leeren Volumes. Keine Fachschemas hier.
psql -v ON_ERROR_STOP=1 --username postgres_admin --dbname postgres <<'SQL'
CREATE ROLE postgres_owner NOLOGIN NOINHERIT;
CREATE ROLE n8n_owner NOLOGIN NOINHERIT;
REVOKE ALL ON DATABASE postgres FROM PUBLIC;
REVOKE ALL ON DATABASE template1 FROM PUBLIC;
CREATE DATABASE cve_monitoring OWNER postgres_owner TEMPLATE template0 ENCODING 'UTF8'
    LOCALE_PROVIDER builtin BUILTIN_LOCALE 'PG_UNICODE_FAST';
CREATE DATABASE n8n OWNER n8n_owner TEMPLATE template0 ENCODING 'UTF8'
    LOCALE_PROVIDER builtin BUILTIN_LOCALE 'PG_UNICODE_FAST';
REVOKE ALL ON DATABASE cve_monitoring FROM PUBLIC;
REVOKE ALL ON DATABASE n8n FROM PUBLIC;
SQL
for database in cve_monitoring n8n; do
    psql -v ON_ERROR_STOP=1 --username postgres_admin --dbname "$database" <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
done
