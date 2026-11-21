"""Actual existing commands, fresh permissions, selectors, processing and immutable audit reads."""

import json
from uuid import uuid4

import pytest

from tests.authorization.integration.conftest import actor, call
from tests.findings.test_native import Harness
from tests.inventory_processor.test_normalization import sample
from tests.inventory_processor.test_processing import drain

pytestmark = pytest.mark.dashboard_administration


async def test_read_selectors_and_real_upload_status(harness: Harness) -> None:
    browser = harness.browser
    finding = await harness.create()
    admin = await actor(browser)
    response = await call(browser, admin, "GET", "administration/upload-options")
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 0
    with browser.lab.owner() as c:
        c.execute(
            (
                "INSERT INTO security.user_server_access(user_id,se"
                "rver_id,can_read,can_upload,findings_read,findings"
                "_manage) VALUES(%s,%s,true,true,true,true)"
            ),
            (admin.id, finding[("server_id")]),
        )
    options = await call(browser, admin, "GET", "administration/upload-options")
    assert options.status_code == 200 and options.json()["total"] >= 1, options.text
    eligible = await call(
        browser, admin, "GET", f"administration/findings/{finding['id']}/assignees"
    )
    assert eligible.status_code == 200, eligible.text
    assert str(admin.id) in [r["id"] for r in eligible.json()["items"]]
    own = await call(browser, admin, "GET", f"administration/users/{admin.id}/roles")
    assert own.status_code == 200 and own.json()["items"]
    audit = await call(browser, admin, "GET", "administration/audit?limit=1")
    assert audit.status_code == 200, audit.text
    assert len(audit.json()["items"]) <= 1 and "metadata" not in str(audit.json())
    preview = await call(
        browser,
        admin,
        ("POST"),
        ("administration/templates/preview"),
        {
            ("name"): ("finding"),
            ("subject"): ("${title}"),
            ("text"): ("${items}"),
            ("html"): ("<p>${items}</p>"),
        },
    )
    assert preview.status_code == 200, preview.text
    bad = await call(
        browser,
        admin,
        ("POST"),
        ("administration/templates/preview"),
        {
            ("name"): ("finding"),
            ("subject"): ("${title}"),
            ("text"): ("${items}"),
            ("html"): ("<img src=x onerror=alert(1)>"),
        },
    )
    assert bad.status_code == 422
    payload = sample()
    payload.update(server_id=str(finding["server_id"]), inventory_id=str(uuid4()))
    upload = await browser.client.post(
        ("/api/v1/dashboard/inventories/upload"),
        data={("server_id"): str(finding[("server_id")])},
        files={("file"): (("phase21.json"), json.dumps(payload).encode(), ("application/json"))},
        headers={
            ("cookie"): ("__Host-cve-session=") + admin.cookie,
            ("x-csrf-token"): admin.csrf,
            ("idempotency-key"): str(uuid4()),
        },
    )
    assert upload.status_code == 202, upload.text
    identity = upload.json()["submission_id"]
    await drain(browser)
    state = await call(browser, admin, "GET", "administration/uploads/" + identity)
    assert state.status_code == 200, state.text
    assert state.json()["processing"]["status"] == "completed"
    lookup = await call(
        browser,
        admin,
        ("GET"),
        ("administration/uploads?inventory_id=") + payload[("inventory_id")],
    )
    assert lookup.status_code == 200 and lookup.json()["items"][0]["submission_id"] == identity
    viewer = await actor(browser, ("viewer",))
    assert (await call(browser, viewer, "GET", "administration/audit")).status_code == 403
    assert (
        await call(browser, viewer, "GET", "administration/uploads/" + identity)
    ).status_code == 404
    assert (
        await call(browser, viewer, ("GET"), f"administration/findings/{finding[('id')]}/assignees")
    ).status_code == 403


async def test_real_browser_administration(harness: Harness) -> None:
    import base64
    import os
    import subprocess

    from scripts.dashboard.manage import activate, node
    from scripts.security.manage import origin

    browser = harness.browser
    finding = await harness.create()
    people = [await actor(browser) for _ in range(4)]
    people.append(await actor(browser, ("user_admin",)))
    people.append(await actor(browser))
    people.append(await actor(browser, ("viewer",)))
    people.append(await actor(browser))
    people.append(await actor(browser))
    with browser.lab.owner() as c:
        c.execute(
            (
                "INSERT INTO security.user_server_access(user_id,se"
                "rver_id,can_read,can_upload,findings_read,findings"
                "_manage) VALUES(%s,%s,true,true,true,true)"
            ),
            (people[5].id, finding["server_id"]),
        )
    # Browser scenarios assert German labels explicitly; production defaults to English.
    with browser.lab.owner() as c:
        c.execute("UPDATE security.instance_preferences SET default_locale='de',version=version+1")
    actors = []
    for person in people:
        with browser.lab.owner() as c:
            method = c.execute(
                (
                    "SELECT key_id,ciphertext,last_used_step FROM secur"
                    "ity.mfa_methods WHERE user_id=%s AND revoked_at IS"
                    " NULL AND verified_at IS NOT NULL"
                ),
                (person.id,),
            ).fetchone()
        secret = (
            base64.b32encode(
                browser.service.keyring.decrypt(
                    person.id, method["key_id"], bytes(method["ciphertext"])
                )
            )
            .decode()
            .rstrip("=")
            if method
            else None
        )
        actors.append(
            {
                "name": person.name,
                "password": person.password,
                "cookie": person.cookie,
                "secret": secret,
                "step": method["last_used_step"] if method else 0,
            }
        )
    payload = sample()
    payload.update(server_id=str(finding["server_id"]), inventory_id=str(uuid4()))
    activate(browser.lab.config)
    binary = node(browser.lab.config.root)
    env = dict(os.environ)
    env.update(
        PATH=str(binary) + os.pathsep + env.get("PATH", ""),
        PLAYWRIGHT_BROWSERS_PATH=str(browser.lab.config.root / ".runtime/playwright"),
        CVE_E2E_URL=origin(browser.lab.config),
        CVE_ADMIN_TEST_ACTORS=json.dumps(actors),
        CVE_E2E_FINDING=str(finding["id"]),
        CVE_E2E_SERVER_ID=str(finding["server_id"]),
        CVE_E2E_SERVER_NAME=str(finding["server_name"]),
        CVE_E2E_INVENTORY=json.dumps(payload),
    )
    log = browser.lab.config.root / ".runtime/test-reports/phase-21-e2e.log"
    with log.open("w") as output:
        result = subprocess.run(
            [
                str(binary / "npm"),
                "--prefix",
                "services/dashboard",
                "run",
                "e2e",
                "--",
                "--config",
                "playwright.administration.config.ts",
            ],
            env=env,
            cwd=browser.lab.config.root,
            stdout=output,
            stderr=subprocess.STDOUT,
            timeout=900,
            check=False,
        )
    assert result.returncode == 0, log.read_text()
    await drain(browser)


async def test_bounded_larger_administrative_bodies(browser: object) -> None:
    from typing import Any, cast

    b = cast(Any, browser)
    admin = await actor(b)
    value = {
        "name": "finding",
        "subject": "${title}",
        "text": "A" * 6000,
        "html": "<p>" + "B" * 6000 + "</p>",
    }
    preview = await call(b, admin, "POST", "administration/templates/preview", value)
    assert preview.status_code == 200, preview.text
    oversized = await b.client.post(
        "/api/v1/dashboard/administration/templates/preview",
        content=b"x" * 32769,
        headers={
            "cookie": "__Host-cve-session=" + admin.cookie,
            "x-csrf-token": admin.csrf,
            "content-type": "application/json",
        },
    )
    assert oversized.status_code == 413
    original = await b.client.post("/api/v1/auth/login", content=b"x" * 8193)
    assert original.status_code == 413
