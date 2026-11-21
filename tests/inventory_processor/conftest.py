"""Reuse the isolated, real API/PKI/PostgreSQL laboratory from acceptance."""

from tests.inventory_upload.integration.conftest import browser, upload_lab

__all__ = ["browser", "upload_lab"]
