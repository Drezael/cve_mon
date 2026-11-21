"""Dedicated PostgreSQL fixture; the development database is never a test target."""

from tests.cve_importer.conftest import import_lab

__all__ = ["import_lab"]
