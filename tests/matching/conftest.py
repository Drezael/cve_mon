"""Reuse real authenticated inventory acceptance in an isolated project only."""

from tests.inventory_upload.integration.conftest import browser, upload_lab

__all__ = ["browser", "upload_lab"]
