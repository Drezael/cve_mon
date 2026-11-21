"""Existing findings expose accurate snapshot-bound software after ACL filtering."""

from typing import Any

import pytest

from tests.authorization.integration.conftest import actor
from tests.findings.test_api import call, grant
from tests.findings.test_native import Harness, harness
from tests.inventory_processor.test_normalization import sample
from tests.inventory_processor.test_processing import drain
from tests.inventory_upload.integration.test_discovery import upload, uploader
from tests.matching.test_container_inventory import inventory

__all__ = ["harness"]
pytestmark = pytest.mark.findings


async def test_existing_host_finding_has_package_name_and_version(harness: Harness) -> None:
    finding = await harness.create()
    viewer = await actor(harness.browser, ("viewer",))
    grant(harness, viewer, finding["server_id"])
    response = await call(harness.browser, viewer, "GET", "/" + str(finding["id"]))
    assert response.status_code == 200
    software = response.json()["affected_software"]
    assert software and software[0]["name"] == "apache2"
    assert software[0]["version"] == "1:2.4.58-1ubuntu8.4"
    assert software[0]["location"] == "host"
    assert software[0]["container_name"] is None
    listing = await call(harness.browser, viewer, "GET", "")
    assert (
        listing.status_code == 200 and listing.json()["items"][0]["affected_software"] == software
    )
    other = await actor(harness.browser, ("viewer",))
    assert (await call(harness.browser, other, "GET", "/" + str(finding["id"]))).status_code == 404
    assert (await call(harness.browser, other, "GET", "")).json()["items"] == []
    admin = await actor(harness.browser)
    updated = await call(
        harness.browser,
        admin,
        "POST",
        "/" + str(finding["id"]) + "/triage",
        {"action": "start", "reason": "Verify software survives finding updates"},
        finding["version"],
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["affected_software"] == software


async def test_same_cve_keeps_host_and_container_software_separate(harness: Harness) -> None:
    browser = harness.browser
    await uploader(browser)
    identity, revision = harness.matcher.seed()
    harness.matcher.enqueue(
        "evaluate_vulnerability", identity=identity, enrichment_revision_id=revision
    )
    await harness.matcher.drain()
    value = inventory()
    package: dict[str, Any] = sample()["packages"]["items"][0]
    package["source_package"] = {"name": "apache2", "version": package["version"]}
    value["packages"]["items"] = [package]
    receipt = await upload(browser, value)
    assert receipt.status_code == 202, receipt.text
    await drain(browser)
    await harness.matcher.drain()
    await harness.drain()
    response = await browser.client.get(
        "/api/v1/findings", params={"server_id": receipt.json()["server_id"], "cve_id": identity}
    )
    assert response.status_code == 200, response.text
    found = response.json()["items"]
    assert len(found) == 1
    software = found[0]["affected_software"]
    assert {s["location"] for s in software} == {"host", "container"}
    assert all(s["name"] == "apache2" for s in software)
    container = next(s for s in software if s["location"] == "container")
    assert container["container_name"] == "web" and container["origin"] == "image"
    assert container["version"] == "1:2.4.58-1ubuntu8.1"
