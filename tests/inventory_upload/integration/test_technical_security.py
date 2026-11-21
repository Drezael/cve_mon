"Real TLS client validation and certificate/token binding, independent of forged HTTP claims."

import ssl
from pathlib import Path
from uuid import uuid4

import pytest

from tests.infrastructure.client import request

from .conftest import Browser, call, create_server, payload, provision, technical

pytestmark = [pytest.mark.inventory_upload, pytest.mark.security]


async def test_real_mtls_acceptance_status_and_header_overwrite(browser: Browser) -> None:
    upload = await provision(browser)
    raw = payload(upload.server["id"])
    cfg = browser.lab.config
    result = request(
        cfg,
        domain=cfg.values["INVENTORY_DOMAIN"],
        path="/api/v1/inventories",
        method="POST",
        client="client",
        body=raw,
        headers={
            "Authorization": "Bearer " + upload.token,
            "Content-Type": "application/json",
            "X-CVE-Inventory-Verify": "FAILED",
            "X-CVE-Inventory-Certificate": "forged",
            "X-CVE-Inventory-Gateway": "forged",
        },
    )
    assert result.status == 202, result.body
    import json

    receipt = json.loads(result.body)
    status = request(
        cfg,
        domain=cfg.values["INVENTORY_DOMAIN"],
        path=receipt["status_url"],
        client="client",
        headers={"Authorization": "Bearer " + upload.token},
    )
    assert status.status == 200, status.body
    assert (
        request(
            cfg,
            domain=cfg.values["INVENTORY_DOMAIN"],
            path="/api/v1/dashboard/admin/servers",
            client="client",
        ).status
        == 404
    )
    assert (
        request(
            cfg,
            domain=cfg.values["API_DOMAIN"],
            path="/api/v1/inventories",
            method="POST",
            body=raw,
        ).status
        == 404
    )


@pytest.mark.parametrize(
    "certificate",
    [None, "untrusted-client", "expired-client", "revoked-client", "wrong-purpose-client"],
)
async def test_real_mtls_rejects_missing_invalid_expired_and_revoked(
    browser: Browser, certificate: str | None
) -> None:
    cfg = browser.lab.config
    try:
        result = request(
            cfg,
            domain=cfg.values["INVENTORY_DOMAIN"],
            path="/api/v1/inventories",
            method="POST",
            client=certificate,
            headers={
                "X-CVE-Inventory-Verify": "SUCCESS",
                "X-CVE-Inventory-Gateway": "invented",
                "Authorization": "Bearer invented",
            },
        )
    except ssl.SSLError:
        return
    assert result.status == 403, result.body


async def test_stolen_bearer_cannot_use_another_valid_certificate(browser: Browser) -> None:
    upload = await provision(browser)
    result = await technical(
        browser, upload, payload(upload.server["id"]), certificate="client-new"
    )
    assert result.status_code == 401, result.text
    cfg = browser.lab.config
    wire_result = request(
        cfg,
        domain=cfg.values["INVENTORY_DOMAIN"],
        path="/api/v1/inventories",
        method="POST",
        client="client-new",
        body=payload(upload.server["id"]),
        headers={"Authorization": "Bearer " + upload.token, "Content-Type": "application/json"},
    )
    assert wire_result.status == 401, wire_result.body


@pytest.mark.parametrize(
    "header", ["x-cve-inventory-gateway", "x-cve-inventory-scheme", "x-cve-inventory-verify"]
)
async def test_direct_backend_identity_claims_need_private_ingress(
    browser: Browser, header: str
) -> None:
    upload = await provision(browser)
    saved = browser.technical_client.headers.pop(header)
    try:
        r = await technical(browser, upload, payload(upload.server["id"]))
    finally:
        browser.technical_client.headers[header] = saved
    assert r.status_code in (401, 403), r.text


async def test_server_and_credential_lifecycle(browser: Browser) -> None:
    upload = await provision(browser)
    other = await create_server(browser, upload.administrator)
    for sid in [other["id"], str(uuid4())]:
        r = await technical(browser, upload, payload(sid))
        assert r.status_code == 404, r.text
    r = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-tokens/" + upload.token_id + "/disable",
        {"reason": "disable test"},
    )
    assert r.status_code == 200
    assert (await technical(browser, upload, payload(upload.server["id"]))).status_code == 401


async def test_token_expiry_client_disable_and_certificate_revocation(browser: Browser) -> None:
    upload = await provision(browser)
    with browser.lab.owner() as c:
        c.execute(
            "UPDATE security.api_tokens SET created_at=clock_timestamp()-inter"
            "val '2 hours',expires_at=clock_timestamp()-inter"
            "val '1 second' WHERE id=%s",
            (upload.token_id,),
        )
    assert (await technical(browser, upload, payload(upload.server["id"]))).status_code == 401
    with browser.lab.owner() as c:
        c.execute(
            "UPDATE security.api_tokens SET expires_at=clock_timestamp()+inter"
            "val '1 hour' WHERE id=%s",
            (upload.token_id,),
        )
    disabled = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-clients/" + upload.client_id + "/disable",
        {"reason": "disabled"},
    )
    assert disabled.status_code == 200
    assert (await technical(browser, upload, payload(upload.server["id"]))).status_code == 401
    assert (
        await call(
            browser,
            upload.administrator,
            "POST",
            "admin/inventory-clients/" + upload.client_id + "/enable",
            {"reason": "restored"},
        )
    ).status_code == 200
    revoked = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-certificates/" + upload.certificate_id + "/revoke",
        {"reason": "revoked"},
    )
    assert revoked.status_code == 200
    assert (await technical(browser, upload, payload(upload.server["id"]))).status_code == 401


async def test_certificate_and_token_rotation_preserve_server_scope(browser: Browser) -> None:
    from datetime import UTC, datetime, timedelta

    upload = await provision(browser)
    pki = Path(browser.lab.config.values["TLS_CERT_FILE"]).parent
    cert = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-clients/" + upload.client_id + "/certificates",
        {"certificate_pem": (pki / "client-new.crt").read_text()},
    )
    assert cert.status_code == 201, cert.text
    rotated = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-tokens/" + upload.token_id + "/rotate",
        {
            "reason": "rotation",
            "certificate_id": cert.json()["id"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert rotated.status_code == 201, rotated.text
    assert rotated.json()["server_id"] == upload.server["id"]
    assert (await technical(browser, upload, payload(upload.server["id"]))).status_code == 401
    assert (
        await technical(
            browser,
            upload,
            payload(upload.server["id"]),
            certificate="client-new",
            token=rotated.json()["token"],
        )
    ).status_code == 202
    listed = await call(
        browser,
        upload.administrator,
        "GET",
        "admin/inventory-clients/" + upload.client_id + "/tokens",
    )
    assert listed.status_code == 200 and all(
        "token" not in row and "verifier" not in row for row in listed.json()["items"]
    )
    with browser.lab.owner() as c:
        row = c.execute(
            "SELECT verifier FROM security.api_tokens WHERE id=%s", (rotated.json()["id"],)
        ).fetchone()
        assert (
            bytes(row["verifier"]) != rotated.json()["token"].encode()
            and len(row["verifier"]) == 32
        )
