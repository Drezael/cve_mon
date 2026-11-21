"Actual bounded HTTP decoding, append-only storage, quotas and native privilege separation."

import json
from uuid import uuid4

import psycopg
import pytest

from scripts.database.manage import connect

from .conftest import Browser, dashboard, payload, provision, technical
from .test_acceptance import uploader

pytestmark = [pytest.mark.inventory_upload, pytest.mark.security]


@pytest.mark.parametrize(
    "raw", [b"", b"{", b"\xff", b'{"a":1,"a":2}', b'{"a":NaN}', b"[" * 40 + b"0" + b"]" * 40]
)
async def test_technical_parser_failures_store_nothing(browser: Browser, raw: bytes) -> None:
    upload = await provision(browser)
    r = await technical(browser, upload, raw)
    assert r.status_code in (400, 422), r.text
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT count(*) AS n FROM inventory.submissions WHERE server_id=%s",
                (upload.server["id"],),
            ).fetchone()["n"]
            == 0
        )


@pytest.mark.parametrize(
    "field", ["group_ids", "primary_group_id", "display_order", "acl", "criticality", "exposure"]
)
async def test_admin_injection_and_schema_rejected_for_both_channels(
    browser: Browser, field: str
) -> None:
    upload = await provision(browser)
    user = await uploader(browser, upload.server["id"])
    raw = json.loads(payload(upload.server["id"]))
    raw["collector"][field] = "forbidden"
    data = json.dumps(raw).encode()
    assert (await technical(browser, upload, data)).status_code == 422
    assert (await dashboard(browser, user, upload.server["id"], data)).status_code == 422


async def test_actual_body_file_and_multipart_limits(browser: Browser) -> None:
    upload = await provision(browser)
    user = await uploader(browser, upload.server["id"])
    browser.inventory.settings = browser.inventory.settings.model_copy(
        update={"max_bytes": 1024, "max_request_bytes": 2048}
    )
    assert (await technical(browser, upload, b" " * 1025)).status_code == 413
    assert (await dashboard(browser, user, upload.server["id"], b" " * 1025)).status_code == 413
    assert (await dashboard(browser, user, upload.server["id"], b" " * 3000)).status_code == 413
    from pathlib import Path
    from urllib.parse import quote

    headers = {
        "authorization": "Bearer " + upload.token,
        "content-type": "application/json",
        "content-encoding": "gzip",
        "x-cve-inventory-certificate": quote(
            (Path(browser.lab.config.values["TLS_CERT_FILE"]).parent / "client.crt").read_text(),
            safe="",
        ),
    }
    r = await browser.technical_client.post(
        "/api/v1/inventories", content=b"not actually gzip", headers=headers
    )
    assert r.status_code == 415, r.text


async def test_rate_limits_and_database_capacity_are_enforced(browser: Browser) -> None:
    upload = await provision(browser)
    browser.inventory.settings = browser.inventory.settings.model_copy(update={"token_rate": 1})
    first = await technical(browser, upload, payload(upload.server["id"]))
    assert first.status_code == 202, first.text
    assert (await technical(browser, upload, payload(upload.server["id"]))).status_code == 429
    browser.inventory.settings = browser.inventory.settings.model_copy(update={"token_rate": 30})
    with browser.lab.owner() as c:
        old = c.execute("SELECT max_count FROM inventory.acceptance_limits").fetchone()["max_count"]
        c.execute("UPDATE inventory.acceptance_limits SET max_count=1")
    try:
        r = await technical(browser, upload, payload(upload.server["id"]))
        assert r.status_code == 429, r.text
    finally:
        with browser.lab.owner() as c:
            c.execute("UPDATE inventory.acceptance_limits SET max_count=%s", (old,))


@pytest.mark.parametrize(
    "role", ["api_ingest", "inventory_processor", "matcher", "event_dispatcher", "status_probe"]
)
async def test_actual_database_principals_cannot_edit_administration_or_credentials(
    browser: Browser, role: str
) -> None:
    for query in [
        "UPDATE inventory.servers SET primary_group_id=NULL",
        "UPDATE inventory.servers SET display_order=0",
        "DELETE FROM inventory.server_group_memberships",
        "UPDATE inventory.server_groups SET name='forbidden'",
        "SELECT * FROM security.api_tokens",
        "SELECT * FROM security.technical_certificates",
        "UPDATE inventory.submissions SET payload_raw=payload_raw",
    ]:
        with (
            connect(browser.lab.config, role) as c,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            c.execute(query)
    # Phase 14 grants only the processor the raw submission read required for normalization.
    with connect(browser.lab.config, role) as c:
        if role == "inventory_processor":
            c.execute("SELECT payload_raw FROM inventory.submissions LIMIT 1").fetchone()
        else:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute("SELECT * FROM inventory.submissions")


async def test_original_payload_and_provenance_immutable_even_for_owner(browser: Browser) -> None:
    upload = await provision(browser)
    r = await technical(browser, upload, payload(upload.server["id"]))
    assert r.status_code == 202, r.text
    sid = r.json()["submission_id"]
    for column, value in [
        ("payload_raw", b"changed"),
        ("source_identity", uuid4()),
        ("server_id", uuid4()),
        ("status", "completed"),
    ]:
        with browser.lab.owner() as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            from psycopg import sql

            c.execute(
                sql.SQL("UPDATE inventory.submissions SET {}=%s WHERE id=%s").format(
                    sql.Identifier(column)
                ),
                (value, sid),
            )
    with connect(browser.lab.config, "status_probe") as c:
        row = c.execute("SELECT security.inventory_metrics() AS stats").fetchone()
        assert row is not None
        stats = row["stats"]
        assert stats["pending_count"] >= 1 and stats["pending_bytes"] >= 1
