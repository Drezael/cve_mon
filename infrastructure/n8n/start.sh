#!/bin/sh
set -eu

# Synchronize before the server activates schedules, webhooks or executions.
node /opt/cve-n8n/bootstrap.cjs
exec /docker-entrypoint.sh "$@"
