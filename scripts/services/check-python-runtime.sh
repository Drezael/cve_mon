#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
exec .venv/bin/python -I -c 'import sys, cve_common, cve_api.factory, fastapi, uvicorn, sqlalchemy, psycopg, httpx; assert sys.version_info[:2] == (3, 12); assert cve_common.__version__ == "0.7.0"; print("Python 3.12 und installierte technische Pakete geprüft")'
