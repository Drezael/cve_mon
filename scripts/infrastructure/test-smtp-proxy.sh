#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
exec .venv/bin/python -m pytest -m egress tests/infrastructure/envoy/test_smtp_tcp_proxy.py "$@"
