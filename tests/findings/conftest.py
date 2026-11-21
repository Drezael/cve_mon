"""Own real mTLS API/PostgreSQL lab; no live inventory, CVEs or findings."""

from tests.inventory_upload.integration.conftest import browser, upload_lab

__all__ = ["browser", "upload_lab"]
