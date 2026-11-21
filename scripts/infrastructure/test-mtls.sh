#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
exec "$ROOT/.venv/bin/python" -m pytest -m infrastructure tests/infrastructure/test_ingress_security.py -k 'mtls or forged or technical or upload_routes' "$@"
