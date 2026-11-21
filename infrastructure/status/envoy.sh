#!/usr/bin/env bash
# Existing private readiness plus a fixed aggregate stats filter; no admin API proxy.
set -uo pipefail
code=0
/opt/cve-envoy/health/check-ready.sh || code=$?
state=healthy
reason=LOCAL_READINESS_CONFIRMED
if [[ "$code" != 0 ]]; then state=unavailable; reason=LOCAL_NOT_READY; fi
failures=null
if exec 4<>/dev/tcp/127.0.0.1/9901; then
    printf 'GET /stats?filter=upstream_cx_connect_fail$ HTTP/1.1\r\nHost: health\r\nConnection: close\r\n\r\n' >&4
    failures=$(head -c 32768 <&4 | awk -F': ' '$2 ~ /^[0-9]+\r?$/ {n+=$2} END {printf "%d", n+0}')
    exec 4<&- 4>&-
fi
if [[ -d /run/cve-status/envoy ]]; then
    stamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    file=/run/cve-status/envoy/observation.json.new
    printf '{"schema_version":1,"service_id":"envoy","check_id":"readiness","checked_at":"%s","result":"%s","duration_ms":0,"reason_code":"%s","metrics":{"upstream_failures":%s}}\n' "$stamp" "$state" "$reason" "$failures" > "$file" && chmod 644 "$file" && mv "$file" /run/cve-status/envoy/observation.json
fi
exit "$code"
