"Two real authorization paths, shared immutable receipts and precise original provenance."

import hashlib
import json
from typing import Any
from uuid import uuid4

import pytest

from .conftest import Browser, actor, dashboard, payload, provision, technical

pytestmark = [pytest.mark.inventory_upload, pytest.mark.security]


async def uploader(browser: Browser, server: str, *, mfa: bool = False) -> Any:
    person = await actor(browser, ("viewer",))
    with browser.lab.owner() as c:
        rid = c.execute(
            "INSERT INTO security.roles(code,name) VALUES(%s,%s) RETURNING id",
            ("upload_" + uuid4().hex, "Upload " + uuid4().hex),
        ).fetchone()["id"]
        c.execute(
            "INSERT INTO security.role_permissions(role_id,permission_code) VA"
            "LUES(%s,'inventory:upload:dashboard')",
            (rid,),
        )
        c.execute(
            "INSERT INTO security.user_roles(user_id,role_id) VALUES(%s,%s)", (person.id, rid)
        )
        c.execute(
            "INSERT INTO security.user_server_access(user_id,server_id,can_rea"
            "d,can_upload) VALUES(%s,%s,true,true)",
            (person.id, server),
        )
    # Native role change invalidates sessions; authenticate again with the new revision.
    logged = await browser.login(person.name, person.password)
    assert logged.status_code == 200
    if mfa or logged.json()["state"] == "mfa_setup_required":
        from tests.authentication.integration.test_flows import enroll

        await enroll(browser)
    person.cookie = browser.client.cookies.get("__Host-cve-session") or ""
    person.csrf = browser.csrf
    return person


async def test_technical_storage_hash_status_duplicate_and_pending_processing(
    browser: Browser,
) -> None:
    upload = await provision(browser)
    raw = payload(upload.server["id"])
    result = await technical(browser, upload, raw)
    assert result.status_code == 202, result.text
    receipt = result.json()
    assert receipt["status"] == "accepted" and not receipt["duplicate"]
    duplicate = await technical(browser, upload, raw)
    assert (
        duplicate.status_code == 202
        and duplicate.json()["submission_id"] == receipt["submission_id"]
        and duplicate.json()["duplicate"]
    )
    changed = json.loads(raw)
    changed["collector"]["version"] = "changed"
    conflict = await technical(browser, upload, json.dumps(changed).encode())
    assert conflict.status_code == 409, conflict.text
    from pathlib import Path
    from urllib.parse import quote

    pki = Path(browser.lab.config.values["TLS_CERT_FILE"]).parent
    status = await browser.technical_client.get(
        receipt["status_url"],
        headers={
            "authorization": "Bearer " + upload.token,
            "x-cve-inventory-certificate": quote((pki / "client.crt").read_text(), safe=""),
        },
    )
    assert status.status_code == 200 and status.json()["status"] == "accepted"
    with browser.lab.owner() as c:
        row = c.execute(
            "SELECT payload_raw,payload_sha256,source,technical_principal_id,t"
            "oken_id,certificate_id,status FROM inventory.submissions WHERE id"
            "=%s",
            (receipt["submission_id"],),
        ).fetchone()
        assert (
            bytes(row["payload_raw"]) == raw
            and bytes(row["payload_sha256"]) == hashlib.sha256(raw).digest()
        )
        assert (
            row["source"] == "ansible_api"
            and str(row["technical_principal_id"]) == upload.client_id
        )
        assert (
            str(row["token_id"]) == upload.token_id
            and str(row["certificate_id"]) == upload.certificate_id
        )
        assert row["status"] == "accepted"
        assert (
            c.execute(
                "SELECT count(*) AS n FROM inventory.snapshots WHERE server_id=%s",
                (upload.server["id"],),
            ).fetchone()["n"]
            == 0
        )
        assert (
            c.execute(
                "SELECT count(*) AS n FROM automation.jobs j JOIN "
                "inventory.submission_processing p ON p.job_id=j.id WHERE "
                "p.submission_id=%s AND j.job_type='inventory.process_submission' "
                "AND j.payload=jsonb_build_object('submission_id',%s::text)",
                (receipt["submission_id"], receipt["submission_id"]),
            ).fetchone()["n"]
            == 1
        )
        assert (
            c.execute(
                "SELECT count(*) AS n FROM security.audit_log WHERE action='invent"
                "ory.accepted' AND object_id=%s",
                (receipt["submission_id"],),
            ).fetchone()["n"]
            == 1
        )
        assert (
            c.execute(
                "SELECT count(*) AS n FROM automation.event_outbox WHERE event_typ"
                "e='inventory.accepted' AND aggregate_id=%s",
                (receipt["submission_id"],),
            ).fetchone()["n"]
            == 1
        )


async def test_dashboard_acl_provenance_and_same_canonical_payload_across_channels(
    browser: Browser,
) -> None:
    upload = await provision(browser)
    user = await uploader(browser, upload.server["id"])
    raw = payload(upload.server["id"])
    technical_result = await technical(browser, upload, raw)
    assert technical_result.status_code == 202, technical_result.text
    formatted = json.dumps(json.loads(raw), indent=2).encode()
    result = await dashboard(browser, user, upload.server["id"], formatted)
    assert result.status_code == 202, result.text
    assert result.json()["submission_id"] != technical_result.json()["submission_id"]
    assert not result.json()["duplicate"]
    duplicate = await dashboard(browser, user, upload.server["id"], raw)
    assert duplicate.status_code == 202 and duplicate.json()["duplicate"]
    with browser.lab.owner() as c:
        row = c.execute(
            "SELECT payload_raw,payload_sha256,actor_user_id,technical_princip"
            "al_id,source,session_reference FROM inventory.submissions WHERE i"
            "d=%s",
            (result.json()["submission_id"],),
        ).fetchone()
        assert (
            bytes(row["payload_raw"]) == formatted
            and bytes(row["payload_sha256"]) == hashlib.sha256(formatted).digest()
        )
        assert (
            row["actor_user_id"] == user.id
            and row["technical_principal_id"] is None
            and row["source"] == "dashboard_file"
        )
        assert str(row["session_reference"]) == user.cookie.split(".")[0]
        before = c.execute(
            "SELECT display_name,primary_group_id,display_order,version FROM i"
            "nventory.servers WHERE id=%s",
            (upload.server["id"],),
        ).fetchone()
        assert before == {
            k: upload.server[k]
            for k in ["display_name", "primary_group_id", "display_order", "version"]
        }
    status = await browser.client.get(
        result.json()["status_url"], headers={"cookie": "__Host-cve-session=" + user.cookie}
    )
    assert status.status_code == 200
    wrong = await browser.client.get(
        technical_result.json()["status_url"].replace("/api/v1/", "/api/v1/dashboard/"),
        headers={"cookie": "__Host-cve-session=" + user.cookie},
    )
    assert wrong.status_code == 404


async def test_admin_inventory_management_needs_no_extra_object_acl(browser: Browser) -> None:
    upload = await provision(browser)
    accepted = await dashboard(
        browser, upload.administrator, upload.server["id"], payload(upload.server["id"])
    )
    assert accepted.status_code == 202, accepted.text
