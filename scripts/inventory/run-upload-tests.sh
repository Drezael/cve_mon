#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
exec .venv/bin/python -m pytest -m inventory_upload tests/inventory_upload/integration "$@"
