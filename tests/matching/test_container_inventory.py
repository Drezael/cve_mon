"""Native upload → persisted SBOM → full/delta matching and ACL container reads."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from tests.inventory_processor.test_processing import drain
from tests.inventory_upload.integration.test_discovery import document, upload, uploader
from tests.matching.test_native import Harness, harness

__all__ = ["harness"]
pytestmark = pytest.mark.matching


def inventory() -> dict[str, Any]:
    value = document()
    value["schema_version"] = "1.3"
    value["packages"] = {"status": "complete", "items": []}
    image = "sha256:" + "c" * 64
    value["containers"] = {
        "status": "complete",
        "items": [
            {
                "container_id": "test-container",
                "name": "web",
                "image_id": image,
                "image_reference": "test:local",
                "state": "running",
                "collection_status": "complete",
            }
        ],
    }
    value["images"] = {
        "status": "complete",
        "items": [{"image_id": image, "references": ["test:local"], "repo_digests": []}],
    }
    value["container_software"] = {
        "status": "complete",
        "items": [
            {
                "container_id": "test-container",
                "image_id": image,
                "scope": "image",
                "status": "complete",
                "captured_at": datetime.now(UTC).isoformat(),
                "document": {
                    "scanner": "syft",
                    "scanner_version": "1.57.1",
                    "os": {"id": "ubuntu", "version": "24.04"},
                    "packages": [
                        {
                            "name": "apache2",
                            "version": "1:2.4.58-1ubuntu8.1",
                            "type": "deb",
                            "source_package": "apache2",
                            "source_version": "1:2.4.58-1ubuntu8.1",
                        }
                    ],
                },
            }
        ],
    }
    return value


async def test_container_only_software_full_scan_delta_and_deduplication(harness: Harness) -> None:
    browser = harness.browser
    await uploader(browser)
    identity, revision = harness.seed()
    harness.enqueue("evaluate_vulnerability", identity=identity, enrichment_revision_id=revision)
    await harness.drain()
    value = inventory()
    received = await upload(browser, value)
    assert received.status_code == 202, received.text
    await drain(browser)
    await harness.drain()
    sid = received.json()["server_id"]
    with browser.lab.owner() as s:
        result = s.execute(
            "SELECT status,result FROM matching.current_evaluations "
            "WHERE server_id=%s AND identity=%s",
            (sid, identity),
        ).fetchone()
        assert result and result["status"] == "affected", result
        assert result["result"]["components"][0]["context"] == "container:test-container"
        count = s.execute("SELECT count(*) AS n FROM inventory.software_bills").fetchone()
        assert count and count["n"] == 1
    response = await browser.client.get(f"/api/v1/dashboard/security/servers/{sid}/containers")
    assert response.status_code == 200, response.text
    assert response.json()["items"][0]["scans"][0]["package_count"] == 1
    packages = await browser.client.get(
        f"/api/v1/dashboard/security/servers/{sid}/container-software?container_id=test-container"
    )
    assert (
        packages.status_code == 200 and packages.json()["items"][0]["package"]["name"] == "apache2"
    )
    # Identical bill in a later snapshot is reused, not duplicated.
    value["inventory_id"] = str(uuid4())
    value["captured_at"] = datetime.now(UTC).isoformat()
    assert (await upload(browser, value)).status_code == 202
    await drain(browser)
    await harness.drain()
    with browser.lab.owner() as s:
        assert s.execute("SELECT count(*) AS n FROM inventory.software_bills").fetchone() == count
    # CVE-first candidate selection must include container software too.
    harness.enqueue("evaluate_vulnerability", identity=identity, enrichment_revision_id=revision)
    await harness.drain()
    await uploader(browser)
    assert (
        await browser.client.get(f"/api/v1/dashboard/security/servers/{sid}/containers")
    ).status_code == 404
