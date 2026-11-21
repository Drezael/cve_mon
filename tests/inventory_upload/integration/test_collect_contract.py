"""Phase-12 collection contract is accepted through both existing protected channels."""

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.database.manage import connect

from .conftest import Browser, dashboard, provision, technical
from .test_acceptance import uploader

pytestmark = [pytest.mark.inventory_upload, pytest.mark.security]


@pytest.mark.parametrize("channel", ["technical", "dashboard"])
async def test_collection_contract_11_roundtrips_immutable_payload(
    browser: Browser, channel: str
) -> None:
    upload = await provision(browser)
    root = Path(__file__).resolve().parents[3]
    value = json.loads((root / "contracts/inventory/examples-v1.1/valid-collect.json").read_text())
    value.update(
        server_id=upload.server["id"],
        inventory_id=str(uuid4()),
        captured_at=datetime.now(UTC).isoformat(),
    )
    raw = json.dumps(value).encode()
    if channel == "technical":
        result = await technical(browser, upload, raw)
    else:
        user = await uploader(browser, upload.server["id"])
        result = await dashboard(browser, user, upload.server["id"], raw)
    assert result.status_code == 202, result.text
    with connect(browser.lab.config) as connection:
        row = connection.execute(
            "SELECT schema_version,payload_json,payload_raw FROM inventory.submissions WHERE id=%s",
            (result.json()["submission_id"],),
        ).fetchone()
        assert row is not None
        assert row["schema_version"] == "1.1" and row["payload_json"] == value
        assert bytes(row["payload_raw"]) == raw


async def test_real_mtls_accepts_packaged_collection_contract(browser: Browser) -> None:
    from tests.infrastructure.client import request

    upload = await provision(browser)
    root = Path(__file__).resolve().parents[3]
    value = json.loads((root / "contracts/inventory/examples-v1.1/valid-collect.json").read_text())
    value.update(
        server_id=upload.server["id"],
        inventory_id=str(uuid4()),
        captured_at=datetime.now(UTC).isoformat(),
    )
    cfg = browser.lab.config
    result = request(
        cfg,
        domain=cfg.values["INVENTORY_DOMAIN"],
        path="/api/v1/inventories",
        method="POST",
        client="client",
        body=json.dumps(value).encode(),
        headers={"Authorization": "Bearer " + upload.token, "Content-Type": "application/json"},
    )
    assert result.status == 202, result.body
    assert json.loads(result.body)["status"] == "accepted"
