#!/bin/sh
# Adapter failure cannot restart or stop mail transport; its report simply becomes stale.
code=0
/opt/cve-mail/healthcheck.sh || code=$?
python3 /opt/cve-status/postfix.py "$code" || true
exit "$code"
