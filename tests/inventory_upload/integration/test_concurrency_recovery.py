"Concurrent idempotency, commit-time revocation and rollback/uncertain acknowledgement."

import asyncio
import json
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from cve_api.inventories import repository
from cve_api.inventories import service as service_module
from cve_api.inventories.errors import UploadError
from cve_api.inventories.events import accepted as accepted_original
from cve_api.inventories.parser import parse as parse_original
from cve_api.technical_auth.certificates import fingerprint, leaf
from cve_api.technical_auth.proxy_identity import TechnicalProof
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from scripts.database.manage import connect
from scripts.infrastructure.manage import compose
from tests.infrastructure.client import Response as WireResponse
from tests.infrastructure.client import request

from .conftest import Browser, call, dashboard, payload, provision, technical
from .test_acceptance import uploader

pytestmark = [pytest.mark.inventory_upload, pytest.mark.security]


def proof_for(browser: Browser, token: str) -> TechnicalProof:
    tid, secret = token.split(".")
    cert = (Path(browser.lab.config.values["TLS_CERT_FILE"]).parent / "client.crt").read_text()
    return TechnicalProof(UUID(tid), secret, fingerprint(leaf(cert)), "192.0.2.19")


@pytest.mark.parametrize("conflicting", [False, True])
async def test_postgres_parallel_idempotency_has_one_success_record(
    browser: Browser, conflicting: bool
) -> None:
    upload = await provision(browser)
    a = payload(upload.server["id"])
    b = a
    if conflicting:
        value = json.loads(a)
        value["collector"]["version"] = "different"
        b = json.dumps(value).encode()
    results = await asyncio.gather(
        browser.inventory.submit_technical(proof_for(browser, upload.token), a, "parallel"),
        browser.inventory.submit_technical(proof_for(browser, upload.token), b, "parallel"),
        return_exceptions=True,
    )
    successes = [r for r in results if isinstance(r, dict)]
    if conflicting:
        assert len(successes) == 1 and any(
            isinstance(r, UploadError) and r.status == 409 for r in results
        )
    else:
        assert (
            len(successes) == 2 and successes[0]["submission_id"] == successes[1]["submission_id"]
        )
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT count(*) AS n FROM inventory.submissions WHERE server_id=%"
                "s AND idempotency_key='parallel'",
                (upload.server["id"],),
            ).fetchone()["n"]
            == 1
        )


async def test_revocation_after_preflight_prevents_commit(
    browser: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    upload = await provision(browser)
    ready = asyncio.Event()
    release = asyncio.Event()
    original = parse_original

    async def waiting(*args: Any, **kwargs: Any) -> object:
        value = await original(*args, **kwargs)
        ready.set()
        await release.wait()
        return value

    monkeypatch.setattr(service_module, "parse", waiting)
    task = asyncio.create_task(technical(browser, upload, payload(upload.server["id"])))
    await asyncio.wait_for(ready.wait(), 20)
    revoked = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-tokens/" + upload.token_id + "/revoke",
        {"reason": "race"},
    )
    assert revoked.status_code == 200
    release.set()
    result = await task
    assert result.status_code == 401, result.text
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT count(*) AS n FROM inventory.submissions WHERE server_id=%s",
                (upload.server["id"],),
            ).fetchone()["n"]
            == 0
        )


async def test_dashboard_acl_revocation_during_parse_prevents_commit(
    browser: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    upload = await provision(browser)
    user = await uploader(browser, upload.server["id"])
    ready = asyncio.Event()
    release = asyncio.Event()
    original = parse_original

    async def waiting(*args: Any, **kwargs: Any) -> object:
        value = await original(*args, **kwargs)
        ready.set()
        await release.wait()
        return value

    monkeypatch.setattr(service_module, "parse", waiting)
    task = asyncio.create_task(
        dashboard(browser, user, upload.server["id"], payload(upload.server["id"]))
    )
    await asyncio.wait_for(ready.wait(), 20)
    revoked = await call(
        browser,
        upload.administrator,
        "PUT",
        "admin/server-access/" + upload.server["id"],
        {"version": 0, "reason": "race", "grants": []},
    )
    assert revoked.status_code == 200
    release.set()
    assert (await task).status_code == 401


async def test_audit_fault_rolls_back_payload_registry_quota_and_outbox(
    browser: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    upload = await provision(browser)
    raw = payload(upload.server["id"])
    original = accepted_original

    async def failing(*args: Any, **kwargs: Any) -> None:
        await original(*args, **kwargs)
        raise RuntimeError("fault after audit")

    monkeypatch.setattr(repository, "accepted", failing)
    with browser.lab.owner() as c:
        before = c.execute(
            "SELECT total_count,total_bytes FROM inventory.acceptance_usage"
        ).fetchone()
    with pytest.raises(RuntimeError):
        await browser.inventory.submit_technical(proof_for(browser, upload.token), raw, "rollback")
    with browser.lab.owner() as c:
        assert (
            c.execute("SELECT total_count,total_bytes FROM inventory.acceptance_usage").fetchone()
            == before
        )
        assert (
            c.execute(
                "SELECT count(*) AS n FROM inventory.submissions WHERE server_id=%s",
                (upload.server["id"],),
            ).fetchone()["n"]
            == 0
        )
        assert (
            c.execute(
                "SELECT count(*) AS n FROM inventory.submission_identities WHERE server_id=%s",
                (upload.server["id"],),
            ).fetchone()["n"]
            == 0
        )


async def test_connection_termination_before_commit_rolls_back(
    browser: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cve_api.auth.repository import execute, one

    upload = await provision(browser)

    async def kill(session: AsyncSession, *args: Any) -> None:
        pid = await one(session, "SELECT pg_backend_pid() AS pid")
        assert pid is not None
        with connect(browser.lab.config, "api_ingest") as c:
            c.execute("SELECT pg_terminate_backend(%s)", (pid["pid"],))
        await execute(session, "SELECT 1")

    monkeypatch.setattr(repository, "accepted", kill)
    with pytest.raises(DBAPIError):
        await browser.inventory.submit_technical(
            proof_for(browser, upload.token), payload(upload.server["id"]), "terminated"
        )
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT count(*) AS n FROM inventory.submissions WHERE server_id=%s",
                (upload.server["id"],),
            ).fetchone()["n"]
            == 0
        )


async def test_lost_ack_retry_finds_committed_submission(
    browser: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    upload = await provision(browser)
    raw = payload(upload.server["id"])
    original = browser.inventory.submit_technical

    async def lost(*args: Any, **kwargs: Any) -> object:
        await original(*args, **kwargs)
        raise UploadError(503, "simulated_lost_ack")

    monkeypatch.setattr(browser.inventory, "submit_technical", lost)
    assert (await technical(browser, upload, raw, key="lost-ack")).status_code == 503
    monkeypatch.setattr(browser.inventory, "submit_technical", original)
    result = await technical(browser, upload, raw, key="lost-ack")
    assert result.status_code == 202 and result.json()["duplicate"]


async def test_real_deployment_upload_restart_outage_and_persistence(browser: Browser) -> None:
    upload = await provision(browser)
    cfg = browser.lab.config
    raw = payload(upload.server["id"])
    headers = {
        "Authorization": "Bearer " + upload.token,
        "Content-Type": "application/json",
        "Idempotency-Key": "restart",
    }

    def send() -> WireResponse:
        return request(
            cfg,
            domain=cfg.values["INVENTORY_DOMAIN"],
            path="/api/v1/inventories",
            method="POST",
            client="client",
            body=raw,
            headers=headers,
        )

    first = send()
    assert first.status == 202, first.body
    sid = json.loads(first.body)["submission_id"]
    compose(cfg, ["restart", "cve-api"])
    compose(cfg, ["up", "-d", "--wait", "--wait-timeout", "45", "cve-api"])
    again = send()
    assert again.status == 202 and json.loads(again.body)["submission_id"] == sid
    compose(cfg, ["restart", "cve-postgres"])
    compose(cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
    assert send().status == 202
    try:
        compose(cfg, ["stop", "cve-postgres"])
        assert send().status == 503
    finally:
        compose(cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
    assert send().status == 202
    revoked = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-tokens/" + upload.token_id + "/revoke",
        {"reason": "end to end"},
    )
    assert revoked.status_code == 200 and send().status == 401


async def test_real_dashboard_mfa_upload_acl_revocation_and_unchanged_groups(
    browser: Browser,
) -> None:
    import httpx

    from tests.server_administration.integration.conftest import assign_groups, create_group

    upload = await provision(browser)
    group = await create_group(browser, upload.administrator)
    assigned = await assign_groups(
        browser, upload.administrator, upload.server["id"], [group["id"]]
    )
    assert assigned.status_code == 200, assigned.text
    user = await uploader(browser, upload.server["id"], mfa=True)
    raw = payload(upload.server["id"])
    cfg = browser.lab.config
    body = httpx.Request(
        "POST",
        "https://example.test",
        data={"server_id": upload.server["id"]},
        files={"file": ("inventory.json", raw, "application/json")},
    )
    encoded = body.read()
    headers = {
        "Cookie": "__Host-cve-session=" + user.cookie,
        "X-CSRF-Token": user.csrf,
        "Origin": browser.service.settings.origin,
        "Content-Type": body.headers["content-type"],
        "Idempotency-Key": "dashboard-e2e",
    }
    with browser.lab.owner() as c:
        before = c.execute(
            "SELECT primary_group_id,display_order,version FROM inventory.servers WHERE id=%s",
            (upload.server["id"],),
        ).fetchone()
    result = request(
        cfg,
        path="/api/v1/dashboard/inventories/upload",
        method="POST",
        body=encoded,
        headers=headers,
    )
    assert result.status == 202, result.body
    value = json.loads(result.body)
    status = request(
        cfg, path=value["status_url"], headers={"Cookie": "__Host-cve-session=" + user.cookie}
    )
    assert status.status == 200, status.body
    with browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT primary_group_id,display_order,version FROM inventory.servers WHERE id=%s",
                (upload.server["id"],),
            ).fetchone()
            == before
        )
        assert (
            c.execute(
                "SELECT display_order FROM inventory.server_group_memberships WHER"
                "E server_id=%s AND group_id=%s",
                (upload.server["id"], group["id"]),
            ).fetchone()["display_order"]
            == 0
        )
    revoked = await call(
        browser,
        upload.administrator,
        "PUT",
        "admin/server-access/" + upload.server["id"],
        {"version": 0, "reason": "e2e revoke", "grants": []},
    )
    assert revoked.status_code == 200
    rejected = request(
        cfg,
        path="/api/v1/dashboard/inventories/upload",
        method="POST",
        body=encoded,
        headers=headers,
    )
    assert rejected.status == 401, rejected.body


async def test_server_archive_during_parse_prevents_acceptance(
    browser: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.server_administration.integration.conftest import send

    upload = await provision(browser)
    ready = asyncio.Event()
    release = asyncio.Event()

    async def waiting(*args: Any, **kwargs: Any) -> Any:
        value = await parse_original(*args, **kwargs)
        ready.set()
        await release.wait()
        return value

    monkeypatch.setattr(service_module, "parse", waiting)
    task = asyncio.create_task(technical(browser, upload, payload(upload.server["id"])))
    await asyncio.wait_for(ready.wait(), 20)
    archived = await send(
        browser,
        upload.administrator,
        "POST",
        "admin/servers/" + upload.server["id"] + "/archive",
        {"reason": "archive race"},
        '"' + str(upload.server["version"]) + '"',
    )
    assert archived.status_code == 200
    release.set()
    result = await task
    assert result.status_code == 409, result.text


async def test_populated_inventory_backup_restore_preserves_payload_and_provenance(
    browser: Browser,
) -> None:
    from scripts.database.manage import backup, restore_test

    upload = await provision(browser)
    received = await technical(browser, upload, payload(upload.server["id"]))
    assert received.status_code == 202
    saved = backup(browser.lab.config, browser.lab.config.directory / "populated-inventory-backup")
    restored = restore_test(browser.lab.config, saved)
    assert restored
