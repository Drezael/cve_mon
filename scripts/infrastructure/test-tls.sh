#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
exec "$ROOT/.venv/bin/python" -m pytest -m infrastructure tests/infrastructure/test_ingress_security.py tests/infrastructure/test_nginx_configuration.py -k 'tls or certificate or headers' "$@"
