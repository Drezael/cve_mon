"""Installed distributions and explicit technical/business import boundaries."""

import ast
import importlib.metadata
import subprocess
import sys
from pathlib import Path


def test_installed_packages_import_without_resources() -> None:
    code = """import socket
def denied(*a, **k): raise RuntimeError("unexpected network")
socket.socket.connect = denied
socket.socket.connect_ex = denied
socket.create_connection = denied
import cve_common, cve_common.database.engine, cve_common.lifecycle.worker
import cve_api.factory, cve_api.main
import cve_event_dispatcher.main, cve_common.jobs.worker, cve_common.events.delivery
assert cve_common.__version__ == "0.7.0"
"""
    subprocess.run([sys.executable, "-c", code], check=True, capture_output=True, cwd="/tmp")
    assert importlib.metadata.version("cve-common") == "0.7.0"
    assert importlib.metadata.version("cve-api") == "0.23.0"


def test_common_has_no_service_imports_or_business_processing() -> None:
    root = Path(__file__).resolve().parents[3]
    for path in (root / "packages/cve_common/src/cve_common").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                assert all(
                    not alias.name.startswith(("cve_api", "services.")) for alias in node.names
                )
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith(("cve_api", "services."))
    # Phase 7 permits the technical dispatcher, never domain-service imports.
