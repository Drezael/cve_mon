#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
exec "$ROOT/.venv/bin/python" -m pytest -m infrastructure tests/infrastructure/test_network_isolation.py "$@"
