"No browser/technical identity substitution, inherited ACL, CSRF or multipart ambiguity."

from uuid import uuid4

import pytest

from .conftest import Browser, actor, call, dashboard, payload, provision
from .test_acceptance import uploader

pytestmark = [pytest.mark.inventory_upload, pytest.mark.security]


@pytest.mark.parametrize("roles", [("viewer",), ("security_analyst",), ("user_admin",)])
async def test_read_roles_do_not_grant_upload_or_credential_administration(
    browser: Browser, roles: tuple[str, ...]
) -> None:
    upload = await provision(browser)
    user = await actor(browser, roles)
    r = await dashboard(browser, user, upload.server["id"], payload(upload.server["id"]))
    assert r.status_code == 403, r.text
    r = await call(browser, user, "POST", "admin/inventory-clients", {"name": "forbidden"})
    assert r.status_code == 403


async def test_missing_session_and_csrf_do_not_accept_bearer(browser: Browser) -> None:
    upload = await provision(browser)
    user = await uploader(browser, upload.server["id"])
    raw = payload(upload.server["id"])
    browser.client.cookies.clear()
    r = await browser.client.post(
        "/api/v1/dashboard/inventories/upload",
        data={"server_id": upload.server["id"]},
        files={"file": ("x.json", raw, "application/json")},
        headers={"authorization": "Bearer " + upload.token},
    )
    assert r.status_code == 403  # Missing CSRF is rejected before body parsing.
    r = await browser.client.post(
        "/api/v1/dashboard/inventories/upload",
        data={"server_id": upload.server["id"]},
        files={"file": ("x.json", raw, "application/json")},
        headers={
            "cookie": "__Host-cve-session=" + user.cookie,
            "x-csrf-token": "wrong-but-sufficient-length",
        },
    )
    assert r.status_code == 403


@pytest.mark.parametrize(
    "filename,mime",
    [
        ("../escape.json", "application/json"),
        ("script.py", "text/x-python"),
        ("archive.zip", "application/zip"),
        ("inventory.json", "application/octet-stream"),
    ],
)
async def test_filename_and_mime_never_select_a_local_path(
    browser: Browser, filename: str, mime: str
) -> None:
    upload = await provision(browser)
    user = await uploader(browser, upload.server["id"])
    r = await dashboard(
        browser,
        user,
        upload.server["id"],
        payload(upload.server["id"]),
        filename=filename,
        mime=mime,
    )
    assert r.status_code == 415, r.text


async def test_extra_files_fields_and_wrong_payload_server_are_rejected(browser: Browser) -> None:
    upload = await provision(browser)
    user = await uploader(browser, upload.server["id"])
    headers = {"cookie": "__Host-cve-session=" + user.cookie, "x-csrf-token": user.csrf}
    raw = payload(upload.server["id"])
    r = await browser.client.post(
        "/api/v1/dashboard/inventories/upload",
        data={"server_id": upload.server["id"], "extra": "bad"},
        files={"file": ("x.json", raw, "application/json")},
        headers=headers,
    )
    assert r.status_code == 400, r.text
    r = await browser.client.post(
        "/api/v1/dashboard/inventories/upload",
        data={"server_id": upload.server["id"]},
        files=[
            ("file", ("x.json", raw, "application/json")),
            ("file", ("y.json", raw, "application/json")),
        ],
        headers=headers,
    )
    assert r.status_code == 400, r.text
    r = await dashboard(browser, user, upload.server["id"], payload(str(uuid4())))
    assert r.status_code == 422, r.text


async def test_own_status_only_and_revoked_acl_cannot_be_reused(browser: Browser) -> None:
    upload = await provision(browser)
    user = await uploader(browser, upload.server["id"])
    other = await uploader(browser, upload.server["id"])
    r = await dashboard(browser, user, upload.server["id"], payload(upload.server["id"]))
    assert r.status_code == 202, r.text
    status = await browser.client.get(
        r.json()["status_url"], headers={"cookie": "__Host-cve-session=" + other.cookie}
    )
    assert status.status_code == 404
    revoke = await call(
        browser,
        upload.administrator,
        "PUT",
        "admin/server-access/" + upload.server["id"],
        {"version": 0, "reason": "revoke upload", "grants": []},
    )
    assert revoke.status_code == 200, revoke.text
    assert (
        await dashboard(browser, user, upload.server["id"], payload(upload.server["id"]))
    ).status_code == 401


async def test_incomplete_mfa_session_cannot_upload(browser: Browser) -> None:
    upload = await provision(browser)
    user = await uploader(browser, upload.server["id"], mfa=True)
    with browser.lab.owner() as c:
        c.execute(
            "UPDATE security.sessions SET auth_state='mfa_pending',mfa_verifie"
            "d_at=NULL WHERE id=%s",
            (user.cookie.split(".")[0],),
        )
    r = await dashboard(browser, user, upload.server["id"], payload(upload.server["id"]))
    assert r.status_code == 403, r.text
