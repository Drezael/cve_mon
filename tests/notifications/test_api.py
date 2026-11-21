"""Real browser sessions, current role/ACL, CSRF, immutable rule versions and actor provenance."""

from typing import Any
from uuid import uuid4

import pytest
from cve_notification.contracts import Rule

from tests.authorization.integration.conftest import Actor, actor, fresh
from tests.notifications.test_native import Harness, harness

__all__ = ["harness"]
pytestmark = pytest.mark.notifications


async def call(
    h: Harness,
    person: Actor,
    method: str,
    path: str,
    body: Any = None,
    version: int | None = None,
    *,
    csrf: bool = True,
) -> Any:
    from cve_api.auth.sessions import SESSION_COOKIE

    if method != "GET":
        fresh(h.browser, person)
    headers = {"cookie": SESSION_COOKIE + "=" + person.cookie}
    if csrf:
        headers["x-csrf-token"] = person.csrf
    if version is not None:
        headers["if-match"] = '"' + str(version) + '"'
    return await h.browser.client.request(
        method, "/api/v1/dashboard/notifications" + path, json=body, headers=headers
    )


async def test_personal_preferences_csrf_etag_and_actor(harness: Harness) -> None:
    viewer = await actor(harness.browser, ("viewer",))
    get = await call(harness, viewer, "GET", "/preferences")
    assert get.status_code == 200
    version = get.json()["version"]
    body: dict[str, Any] = {
        "preferences": {"mode": "digest", "timezone": "Europe/Berlin"},
        "reason": "Persönliche Benachrichtigungen konfigurieren",
    }
    assert (
        await call(harness, viewer, "PUT", "/preferences", body, version, csrf=False)
    ).status_code == 403
    assert (await call(harness, viewer, "PUT", "/preferences", body)).status_code == 428
    put = await call(harness, viewer, "PUT", "/preferences", body, version)
    assert put.status_code == 200, put.text
    assert put.json()["user_id"] == str(viewer.id)
    assert (await call(harness, viewer, "PUT", "/preferences", body, version)).status_code == 412
    assert (
        await call(
            harness, viewer, "PUT", "/preferences", {**body, "user_id": str(uuid4())}, version + 1
        )
    ).status_code == 422
    with harness.browser.lab.owner() as c:
        audit = c.execute(
            (
                "SELECT * FROM automation.notification_audit WHERE "
                "object_id=%s AND action='preferences' ORDER BY occ"
                "urred_at DESC LIMIT 1"
            ),
            (viewer.id,),
        ).fetchone()
        assert audit["actor_user_id"] == viewer.id


async def test_only_admin_can_version_rules_and_templates(harness: Harness) -> None:
    admin = await actor(harness.browser)
    viewer = await actor(harness.browser, ("viewer",))
    user_admin = await actor(harness.browser, ("user_admin",))
    body: dict[str, Any] = {
        "rule": Rule(recipients="authorized").model_dump(mode="json"),
        "reason": "Explizite Testfreigabe",
    }
    for person in [viewer, user_admin]:
        assert (await call(harness, person, "POST", "/rules", body, 0)).status_code == 403
    created = await call(harness, admin, "POST", "/rules", body, 0)
    assert created.status_code == 200, created.text
    row = created.json()
    changed = await call(
        harness,
        admin,
        "PUT",
        "/rules/" + row["rule_key"],
        {**body, "rule": {**body["rule"], "enabled": False}},
        row["version"],
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["version"] == 2 and changed.json()["id"] != row["id"]
    assert (
        await call(harness, admin, "PUT", "/rules/" + row["rule_key"], body, 1)
    ).status_code == 412
    assert (await call(harness, viewer, "GET", "/templates")).status_code == 403
    assert (await call(harness, admin, "GET", "/templates")).status_code == 200


async def test_personal_list_counts_and_history_never_expose_other_recipient(
    harness: Harness,
) -> None:
    viewer = await actor(harness.browser, ("viewer",))
    other = await actor(harness.browser, ("viewer",))
    harness.enable()
    f = await harness.findings.create()
    with harness.browser.lab.owner() as c:
        c.execute(
            (
                "INSERT INTO security.user_server_access(user_id,se"
                "rver_id,can_read,findings_read) VALUES(%s,%s,true,"
                "true)"
            ),
            (viewer.id, f["server_id"]),
        )
    await harness.drain()
    own = await call(harness, viewer, "GET", "")
    assert own.status_code == 200, own.text
    assert own.json()["total"] > 0
    assert all(n["recipient_user_id"] == str(viewer.id) for n in own.json()["items"])
    identity = own.json()["items"][0]["id"]
    assert (await call(harness, viewer, "GET", "/" + identity + "/history")).status_code == 200
    assert (await call(harness, other, "GET", "/" + identity)).status_code == 404
    assert (await call(harness, other, "GET", "")).json()["total"] == 0
    with harness.browser.lab.owner() as c:
        c.execute("DELETE FROM security.user_server_access WHERE user_id=%s", (viewer.id,))
    assert (await call(harness, viewer, "GET", "")).json()["total"] == 0
    assert (await call(harness, viewer, "GET", "/" + identity + "/history")).status_code == 404
    assert (
        await call(harness, viewer, "GET", "?order=desc;DROP TABLE security.users")
    ).status_code == 422


async def test_actual_https_notification_gate_and_authenticated_preferences(
    harness: Harness,
) -> None:
    from cve_api.auth.sessions import SESSION_COOKIE

    from scripts.infrastructure.manage import run

    admin = await actor(harness.browser)
    cfg = harness.browser.lab.config
    host = cfg.values["DASHBOARD_DOMAIN"]
    port = cfg.values["INGRESS_HTTPS_PORT"]
    args = [
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        "10",
        "--cacert",
        cfg.values["TLS_TRUST_FILE"],
        "--resolve",
        f"{host}:{port}:127.0.0.1",
        "--config",
        "-",
        "--write-out",
        "\n%{http_code}",
        f"https://{host}:{port}/api/v1/dashboard/notifications/preferences",
    ]
    anonymous = run(args, input="")
    assert anonymous.stdout.rsplit("\n", 1)[1] == "401"
    authenticated = run(args, input=f'header = "Cookie: {SESSION_COOKIE}={admin.cookie}"\n')
    assert authenticated.stdout.rsplit("\n", 1)[1] == "200"


async def test_weekly_settings_are_personal_persistent_and_versioned(harness: Harness) -> None:
    viewer = await actor(harness.browser, ("viewer",))
    get = await call(harness, viewer, "GET", "/reports/schedule")
    assert get.status_code == 200
    body = {"enabled": True, "weekday": 4, "time": "17:45", "timezone": "Europe/Berlin"}
    version = get.json()["version"]
    assert (
        await call(harness, viewer, "PUT", "/reports/schedule", body, version, csrf=False)
    ).status_code == 403
    assert (await call(harness, viewer, "PUT", "/reports/schedule", body)).status_code == 428
    saved = await call(harness, viewer, "PUT", "/reports/schedule", body, version)
    assert saved.status_code == 200, saved.text
    assert saved.json()["configuration"] == body
    assert (
        await call(harness, viewer, "PUT", "/reports/schedule", body, version)
    ).status_code == 412
    loaded = await call(harness, viewer, "GET", "/reports/schedule")
    assert loaded.json()["configuration"] == body
    assert (
        await call(
            harness,
            viewer,
            "PUT",
            "/reports/schedule",
            {**body, "time": "25:00"},
            saved.json()["version"],
        )
    ).status_code == 422
    other = await actor(harness.browser, ("viewer",))
    own = await call(harness, other, "GET", "/reports/schedule")
    assert own.json()["configuration"] != body


async def test_report_request_is_idempotent_scoped_and_queued(harness: Harness) -> None:
    viewer = await actor(harness.browser, ("viewer",))
    key = str(uuid4())
    headers = {
        "cookie": "__Host-cve-session=" + viewer.cookie,
        "x-csrf-token": viewer.csrf,
        "Idempotency-Key": key,
    }
    first = await harness.browser.client.post(
        "/api/v1/dashboard/notifications/reports/request", headers=headers
    )
    assert first.status_code == 202, first.text
    again = await harness.browser.client.post(
        "/api/v1/dashboard/notifications/reports/request", headers=headers
    )
    assert again.json() == first.json()
    history = await call(harness, viewer, "GET", "/reports")
    assert history.status_code == 200
    assert any(r["id"] == key for r in history.json()["items"])
    other = await actor(harness.browser, ("viewer",))
    hidden = await call(harness, other, "GET", "/reports")
    assert not any(r["id"] == key for r in hidden.json()["items"])
    with harness.browser.lab.owner() as s:
        assert s.execute(
            "SELECT state FROM automation.mail_reports WHERE id=%s", (key,)
        ).fetchone() == {"state": "requested"}
        assert s.execute(
            "SELECT count(*) n FROM automation.n8n_queue "
            "WHERE message_type='reports.scan' AND correlation_id=%s",
            (key,),
        ).fetchone() == {"n": 1}
