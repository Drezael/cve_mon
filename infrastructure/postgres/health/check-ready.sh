#!/usr/bin/env bash
set -euo pipefail
if [[ $(id -u) == 0 ]]; then
    exec gosu postgres "$0"
fi
# Verfügbarkeit, nicht Fachschema-/Migrationsbereitschaft; Peer-Auth ohne Passwort.
exec pg_isready -q -h /var/run/postgresql -U postgres_admin -d postgres
