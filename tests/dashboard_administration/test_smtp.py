"""Real sessions, encrypted SMTP configuration, idempotency and n8n fencing."""

import secrets
from uuid import uuid4

import pytest

from scripts.database import manage as db
from tests.authorization.integration.conftest import actor
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.dashboard_administration
BASE = "/api/v1/dashboard/administration/smtp"


async def test_smtp_settings_are_private_encrypted_and_wait_for_n8n(browser: Browser) -> None:
    admin = await actor(browser)
    headers = {
        "cookie": "__Host-cve-session=" + admin.cookie,
        "x-csrf-token": admin.csrf,
        "Idempotency-Key": str(uuid4()),
    }
    initial = await browser.client.get(BASE, headers=headers)
    assert initial.status_code == 200, initial.text
    assert initial.json()["version"] == 0 and not initial.json()["password_configured"]
    secret = secrets.token_urlsafe(32)
    payload = {
        "version": 0,
        "enabled": False,
        "host": "smtp.example.test",
        "port": 587,
        "sender": "security@example.test",
        "recipients": ["user@example.test"],
        "username": "smtp-account",
        "password": secret,
    }
    denied = await browser.client.put(
        BASE,
        headers={"cookie": headers["cookie"], "Idempotency-Key": headers["Idempotency-Key"]},
        json=payload,
    )
    assert denied.status_code == 403
    with browser.lab.owner() as s:
        s.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
    response = await browser.client.put(BASE, headers=headers, json=payload)
    assert response.status_code == 202, response.text
    value = response.json()
    assert value["state"] == "waiting" and value["password_configured"]
    assert secret not in response.text and "credentials" not in value
    repeated = await browser.client.put(BASE, headers=headers, json=payload)
    assert repeated.status_code == 202 and repeated.json()["id"] == value["id"]
    identity = value["id"]
    with browser.lab.owner() as s:
        row = s.execute(
            "SELECT credentials,key_id,queue_id FROM automation.smtp_configs WHERE id=%s",
            (identity,),
        ).fetchone()
        assert row and secret.encode() not in bytes(row["credentials"])
        queued = s.execute(
            "SELECT payload,state FROM automation.n8n_queue WHERE id=%s", (row["queue_id"],)
        ).fetchone()
        assert queued and queued["state"] == "pending" and secret not in str(queued["payload"])
    with db.connect(browser.lab.config, "dashboard_admin") as s:
        row = s.execute("SELECT automation.claim_smtp() AS id").fetchone()
        assert row and row["id"] is None
    for _ in range(50):
        with db.connect(browser.lab.config, "workflow_control") as s:
            row = s.execute(
                "SELECT automation.n8n_claim('smtp-native','cve-control-queue') AS value"
            ).fetchone()
            assert row and row["value"]["kind"] != "empty"
            item = row["value"]
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,%s,%s)",
                (item["id"], item["lease_token"], item["kind"], "smtp-native", "cve-control-queue"),
            )
        if item["message_type"] == "smtp.configure":
            break
    else:
        raise AssertionError("SMTP command did not reach FIFO head")
    with browser.lab.owner() as s:
        s.execute(
            "UPDATE automation.n8n_queue SET finished_at=clock_timestamp()-interval '3 seconds' "
            "WHERE correlation_id=%s",
            (identity,),
        )
    with db.connect(browser.lab.config, "dashboard_admin") as s:
        row = s.execute("SELECT automation.claim_smtp() AS id").fetchone()
        assert row and str(row["id"]) == identity
        token = s.execute(
            "SELECT lease_token FROM automation.smtp_configs WHERE id=%s", (identity,)
        ).fetchone()
        assert token
        s.execute("SELECT automation.finish_smtp(%s,%s,NULL)", (identity, token["lease_token"]))
    status = await browser.client.get(BASE, headers=headers)
    assert status.json()["state"] == "applied" and secret not in status.text
    # A blank password retains the encrypted secret across a new configuration version.
    next_payload = {**payload, "version": 1, "password": None}
    next_response = await browser.client.put(
        BASE, headers={**headers, "Idempotency-Key": str(uuid4())}, json=next_payload
    )
    assert next_response.status_code == 202 and next_response.json()["password_configured"]
    assert secret not in next_response.text
    reader = await actor(browser, ("security_analyst",))
    assert (
        await browser.client.get(BASE, headers={"cookie": "__Host-cve-session=" + reader.cookie})
    ).status_code == 403


async def test_personal_mail_is_owner_scoped_and_uses_the_same_n8n_queue(browser: Browser) -> None:
    first = await actor(browser, ("viewer",))
    second = await actor(browser, ("security_analyst",))
    personal = "/api/v1/dashboard/notifications/mail"

    def headers(person: object) -> dict[str, str]:
        from tests.authorization.integration.conftest import Actor

        assert isinstance(person, Actor)
        return {
            "cookie": "__Host-cve-session=" + person.cookie,
            "x-csrf-token": person.csrf,
            "Idempotency-Key": str(uuid4()),
        }

    first_headers, second_headers = headers(first), headers(second)
    initial = await browser.client.get(personal, headers=first_headers)
    assert initial.status_code == 200 and initial.json()["mode"] == "system"
    assert "password" not in initial.json() and "credentials" not in initial.text
    password = secrets.token_urlsafe(32)
    body = {
        "version": 0,
        "mode": "custom",
        "enabled": True,
        "host": "smtp.personal.example.org",
        "port": 587,
        "sender": "first@example.org",
        "username": "first-account",
        "password": password,
        "recipients": ["first@example.org", "alerts@example.org", "first@example.org"],
    }
    denied = await browser.client.put(
        personal,
        headers={
            "cookie": first_headers["cookie"],
            "Idempotency-Key": first_headers["Idempotency-Key"],
        },
        json=body,
    )
    assert denied.status_code == 403
    requested = await browser.client.put(personal, headers=first_headers, json=body)
    assert requested.status_code == 202, requested.text
    result = requested.json()
    assert result["recipients"] == ["alerts@example.org", "first@example.org"]
    assert result["state"] == "waiting" and result["password_configured"]
    assert password not in requested.text
    repeated = await browser.client.put(personal, headers=first_headers, json=body)
    assert repeated.status_code == 202 and repeated.json()["id"] == result["id"]
    other = await browser.client.get(personal, headers=second_headers)
    assert other.json()["version"] == 0 and other.json()["username"] == ""
    collision = await browser.client.put(
        personal,
        headers={**second_headers, "Idempotency-Key": first_headers["Idempotency-Key"]},
        json=body,
    )
    assert collision.status_code == 409 and password not in collision.text
    # A second user can save while the first user's command is still pending.
    system_body = {
        **body,
        "mode": "system",
        "enabled": False,
        "username": "",
        "password": None,
        "host": "",
        "sender": "",
        "recipients": ["second@example.org", "team@example.org"],
    }
    second_save = await browser.client.put(personal, headers=second_headers, json=system_body)
    assert second_save.status_code == 202, second_save.text
    assert second_save.json()["version"] == 1 and not second_save.json()["password_configured"]
    assert (await browser.client.get(BASE, headers=first_headers)).status_code == 403
    assert (
        await browser.client.put(
            BASE, headers=first_headers, json={k: v for k, v in body.items() if k != "mode"}
        )
    ).status_code == 403
    for invalid in [
        {**body, "owner_id": str(second.id)},
        {**body, "password": password + "\n"},
        {**body, "recipients": []},
        {**body, "recipients": [f"user{i}@example.org" for i in range(21)]},
        {**body, "recipients": ["bad\nBcc: victim@example.org"]},
    ]:
        response = await browser.client.put(personal, headers=headers(first), json=invalid)
        assert response.status_code == 422
        assert password not in response.text
    with browser.lab.owner() as s:
        stored = s.execute(
            "SELECT owner_id,credentials,queue_id FROM automation.smtp_configs WHERE id=%s",
            (result["id"],),
        ).fetchone()
        assert (
            stored
            and stored["owner_id"] == first.id
            and password.encode() not in bytes(stored["credentials"])
        )
        queued = s.execute(
            "SELECT payload,state FROM automation.n8n_queue WHERE id=%s", (stored["queue_id"],)
        ).fetchone()
        assert queued and queued["state"] == "pending"
        assert set(queued["payload"]) == {"configuration_id", "version"}
    # n8n authorization uses personal permission, not the administrative SMTP grant.
    with browser.lab.owner() as s:
        s.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
    for _ in range(100):
        with db.connect(browser.lab.config, "workflow_control") as s:
            claimed = s.execute(
                "SELECT automation.n8n_claim('personal-mail-native','cve-control-queue') AS value"
            ).fetchone()
            assert claimed
            item = claimed["value"]
            assert item["kind"] != "empty"
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,%s,%s)",
                (
                    item["id"],
                    item["lease_token"],
                    item["kind"],
                    "personal-mail-native",
                    "cve-control-queue",
                ),
            )
        if str(item["id"]) == str(stored["queue_id"]):
            break
    else:
        raise AssertionError("personal SMTP command was not processed")
    state = await browser.client.get(personal, headers=first_headers)
    assert state.json()["state"] == "authorized" and password not in state.text


async def test_instance_administration_role_boundaries(browser: Browser) -> None:
    """Direct API URLs never turn inventory access into instance administration."""
    paths = (
        "/api/v1/dashboard/admin/users",
        "/api/v1/dashboard/admin/roles",
        BASE,
        "/api/v1/dashboard/administration/audit",
        "/api/v1/dashboard/notifications/rules",
        "/api/v1/dashboard/notifications/templates",
    )
    for role in ("viewer", "user_admin", "admin"):
        person = await actor(browser, (role,))
        headers = {"cookie": "__Host-cve-session=" + person.cookie}
        for path in paths:
            response = await browser.client.get(path, headers=headers)
            allowed = role == "admin" or (
                role == "user_admin" and path in (paths[0], paths[1], paths[3])
            )
            assert response.status_code == (200 if allowed else 403), (role, path)
        if role == "viewer":
            for path in (
                "/api/v1/dashboard/admin/servers",
                "/api/v1/dashboard/notifications/preferences",
                "/api/v1/dashboard/notifications/mail",
            ):
                response = await browser.client.get(path, headers=headers)
                assert response.status_code == 200, path
