"""Real first-start Compose defaults, persisted precedence, and fenced test commands."""

import json
import secrets
from collections.abc import Iterator
from dataclasses import replace
from typing import Any
from uuid import uuid4

import pytest

from scripts.database import manage as db
from scripts.infrastructure.manage import compose
from tests.authentication.integration.conftest import Lab
from tests.authorization.integration.conftest import actor
from tests.inventory_upload.integration.conftest import Browser, isolated_upload_lab

pytestmark = pytest.mark.dashboard_administration
BASE = "/api/v1/dashboard/administration/smtp"
PERSONAL = "/api/v1/dashboard/notifications/mail"


@pytest.fixture(scope="module")
def upload_lab() -> Iterator[Lab]:
    yield from isolated_upload_lab(
        {
            "SMTP_HOST": "smtp.bootstrap.example.test",
            "SMTP_PORT": "587",
            "SMTP_SENDER": "monitor@example.test",
            "SMTP_USERNAME": "initial-account",
            "SMTP_PASSWORD": secrets.token_urlsafe(32),
        }
    )


def required(cursor: Any) -> dict[str, Any]:
    row: dict[str, Any] | None = cursor.fetchone()
    assert row is not None
    return row


def authorize_and_apply(lab: Lab, identity: str) -> None:
    with lab.owner() as s:
        s.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
    for _ in range(200):
        with db.connect(lab.config, "workflow_control") as s:
            item = required(
                s.execute(
                    "SELECT automation.n8n_claim('smtp-test-fixture','cve-control-queue') AS value"
                )
            )["value"]
            assert item["kind"] != "empty"
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,%s,%s)",
                (
                    item["id"],
                    item["lease_token"],
                    item["kind"],
                    "smtp-test-fixture",
                    "cve-control-queue",
                ),
            )
        if (
            str(item["payload"].get("configuration_id") or item["payload"].get("test_id"))
            == identity
        ):
            break
    else:
        raise AssertionError("SMTP request did not reach FIFO head")
    with lab.owner() as s:
        s.execute(
            "UPDATE automation.n8n_queue SET finished_at=clock_timestamp()-interval '3 seconds' "
            "WHERE correlation_id=%s",
            (identity,),
        )
    with db.connect(lab.config, "dashboard_admin") as s:
        row = required(s.execute("SELECT automation.claim_smtp() AS id"))
        assert str(row["id"]) == identity
        token = required(
            s.execute("SELECT lease_token FROM automation.smtp_configs WHERE id=%s", (identity,))
        )["lease_token"]
        s.execute("SELECT automation.finish_smtp(%s,%s,NULL)", (identity, token))


async def test_compose_bootstrap_and_saved_disabled_settings_survive_recreation(
    browser: Browser,
) -> None:
    admin = await actor(browser)
    headers = {
        "cookie": "__Host-cve-session=" + admin.cookie,
        "x-csrf-token": admin.csrf,
        "Idempotency-Key": str(uuid4()),
    }
    first = await browser.client.get(BASE, headers=headers)
    assert first.status_code == 200, first.text
    value = first.json()
    assert value["version"] == 1 and value["state"] == "waiting"
    assert value["host"] == "smtp.bootstrap.example.test" and value["password_configured"]
    password = browser.lab.config.values["SMTP_PASSWORD"]
    assert password not in first.text
    with browser.lab.owner() as s:
        row = required(
            s.execute("SELECT * FROM automation.smtp_configs WHERE id=%s", (value["id"],))
        )
        assert row["origin"] == "environment" and row["requested_by"] is None
        assert password.encode() not in bytes(row["credentials"])
        audit = required(
            s.execute(
                "SELECT technical_principal_id,actor_user_id FROM security.audit_log "
                "WHERE object_id=%s",
                (value["id"],),
            )
        )
        assert audit["technical_principal_id"] and audit["actor_user_id"] is None
    authorize_and_apply(browser.lab, value["id"])
    response = await browser.client.put(
        BASE,
        headers=headers,
        json={
            "version": 1,
            "enabled": False,
            "host": "smtp.saved.example.test",
            "sender": "saved@example.test",
            "username": "saved-account",
            "password": None,
            "port": 587,
            "recipients": [],
        },
    )
    assert response.status_code == 202, response.text
    authorize_and_apply(browser.lab, response.json()["id"])
    # Same environment on a plain restart, then invalid replacement values on recreation.
    compose(browser.lab.config, ["restart", "cve-api"])
    compose(browser.lab.config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-api"])
    override = (
        browser.lab.config.root / ".runtime" / (browser.lab.config.project + "-smtp-bootstrap.yml")
    )
    override.write_text(
        "services:\n  cve-api:\n    environment:\n"
        "      CVE_SMTP_HOST: invalid://ignored\n      CVE_SMTP_PORT: invalid\n"
        "      CVE_SMTP_PASSWORD: ignored\n"
    )
    changed = replace(
        browser.lab.config, compose_overrides=(*browser.lab.config.compose_overrides, override)
    )
    try:
        compose(
            changed,
            [
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "--wait",
                "--wait-timeout",
                "60",
                "cve-api",
            ],
        )
        final = await browser.client.get(BASE, headers=headers)
        assert final.status_code == 200, final.text
        saved = final.json()
        assert saved["version"] == 2 and saved["state"] == "applied" and not saved["enabled"]
        assert saved["host"] == "smtp.saved.example.test" and saved["username"] == "saved-account"
        with browser.lab.owner() as s:
            assert (
                required(
                    s.execute(
                        "SELECT count(*) AS n FROM automation.smtp_configs WHERE owner_id IS NULL"
                    )
                )["n"]
                == 2
            )
    finally:
        override.unlink(missing_ok=True)


async def test_test_mail_is_owner_scoped_idempotent_and_waits_for_n8n(browser: Browser) -> None:
    user = await actor(browser, ("viewer",))
    other = await actor(browser, ("viewer",))
    headers = {
        "cookie": "__Host-cve-session=" + user.cookie,
        "x-csrf-token": user.csrf,
        "Idempotency-Key": str(uuid4()),
    }
    config = await browser.client.put(
        PERSONAL,
        headers=headers,
        json={
            "version": 0,
            "mode": "custom",
            "enabled": True,
            "host": "smtp.personal.example.test",
            "sender": "user@example.test",
            "username": "personal",
            "password": secrets.token_urlsafe(32),
            "recipients": ["one@example.test", "two@example.test"],
        },
    )
    assert config.status_code == 202, config.text
    authorize_and_apply(browser.lab, config.json()["id"])
    h = {**headers, "Idempotency-Key": str(uuid4())}
    assert (
        await browser.client.post(
            PERSONAL + "/test",
            headers={"cookie": headers["cookie"], "Idempotency-Key": h["Idempotency-Key"]},
            json={},
        )
    ).status_code == 403
    assert (await browser.client.post(BASE + "/test", headers=h, json={})).status_code == 403
    response = await browser.client.post(PERSONAL + "/test", headers=h, json={})
    assert response.status_code == 202, response.text
    identity = response.json()["id"]
    assert response.json()["state"] == "waiting"
    assert (await browser.client.post(PERSONAL + "/test", headers=h, json={})).json()[
        "id"
    ] == identity
    other_headers = {
        "cookie": "__Host-cve-session=" + other.cookie,
        "x-csrf-token": other.csrf,
        "Idempotency-Key": h["Idempotency-Key"],
    }
    assert (
        await browser.client.post(PERSONAL + "/test", headers=other_headers, json={})
    ).status_code == 409
    assert (await browser.client.get(PERSONAL + "/test", headers=other_headers)).json()[
        "state"
    ] == "unconfigured"
    for body in [
        {"recipient": "bad\nBcc: other@example.test"},
        {"password": secrets.token_urlsafe(32)},
    ]:
        assert (
            await browser.client.post(
                PERSONAL + "/test", headers={**h, "Idempotency-Key": str(uuid4())}, json=body
            )
        ).status_code == 422
    with db.connect(browser.lab.config, "dashboard_admin") as s:
        assert required(s.execute("SELECT automation.claim_smtp_test() AS id"))["id"] is None
    with browser.lab.owner() as s:
        row = required(
            s.execute(
                "SELECT t.*,q.payload FROM automation.smtp_tests t JOIN automation.n8n_queue q "
                "ON q.id=t.queue_id WHERE t.id=%s",
                (identity,),
            )
        )
        assert row["recipients"] == ["one@example.test", "two@example.test"]
        assert row["payload"] == {"test_id": identity} and "password" not in json.dumps(
            row["payload"]
        )
    for _ in range(200):
        with db.connect(browser.lab.config, "workflow_control") as s:
            item = required(
                s.execute(
                    "SELECT automation.n8n_claim('smtp-native-test','cve-control-queue') AS value"
                )
            )["value"]
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,%s,%s)",
                (
                    item["id"],
                    item["lease_token"],
                    item["kind"],
                    "smtp-native-test",
                    "cve-control-queue",
                ),
            )
        if (
            str(item["payload"].get("configuration_id") or item["payload"].get("test_id"))
            == identity
        ):
            break
    with db.connect(browser.lab.config, "dashboard_admin") as s:
        assert (
            str(required(s.execute("SELECT automation.claim_smtp_test() AS id"))["id"]) == identity
        )
        token = required(
            s.execute("SELECT lease_token FROM automation.smtp_tests WHERE id=%s", (identity,))
        )["lease_token"]
        s.execute(
            "SELECT automation.finish_smtp_test(%s,%s,'SMTP_AUTHENTICATION_FAILED')",
            (identity, token),
        )
    result = await browser.client.get(PERSONAL + "/test", headers=h)
    assert (
        result.json()["state"] == "failed"
        and result.json()["error_code"] == "SMTP_AUTHENTICATION_FAILED"
    )
