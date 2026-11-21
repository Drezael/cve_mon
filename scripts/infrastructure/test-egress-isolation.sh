#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
exec .venv/bin/python -m pytest -m egress tests/infrastructure/envoy/test_network_isolation.py "$@"
