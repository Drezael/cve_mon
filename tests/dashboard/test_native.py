"""Real TLS APIs, scoped aggregates and existing immutable domain evidence."""

import os
import subprocess
from typing import Any
from uuid import uuid4

import pytest

from tests.authorization.integration.conftest import actor
from tests.authorization.integration.conftest import call as dashboard_call
from tests.findings.test_native import Harness


async def call(browser: Any, person: Any, method: str, path: str) -> Any:
    return await dashboard_call(browser, person, method, path.removeprefix("/api/v1/dashboard/"))


pytestmark = pytest.mark.dashboard


async def test_scoped_dashboard_and_source_context(harness: Harness) -> None:
    browser = harness.browser
    from tests.notifications.test_native import Harness as NotificationHarness

    notifications = NotificationHarness(browser)
    await notifications.findings.database.close()
    await notifications.findings.matcher.database.close()
    notifications.findings = harness
    notifications.enable()
    try:
        f = await harness.create()
        admin = await actor(browser)
        await notifications.drain()
    finally:
        await notifications.database.close()
    own_notifications = await call(browser, admin, "GET", "/api/v1/dashboard/notifications?limit=1")
    assert own_notifications.status_code == 200, own_notifications.text
    assert own_notifications.json()["total"] > 0
    notification = own_notifications.json()["items"][0]
    # Current notifications summarize a complete server scan, rather than one CVE.
    assert notification["finding_id"] is None
    assert notification["cve_id"] is None and notification["server_id"] is None
    with browser.lab.owner() as c:
        report = c.execute(
            "SELECT r.origin,s.server_id,s.snapshot_id FROM automation.mail_reports r "
            "JOIN automation.mail_report_servers s ON s.report_id=r.id "
            "WHERE r.notification_id=%s AND s.server_id=%s",
            (notification["id"], f["server_id"]),
        ).fetchone()
        assert report and report["origin"] == "scan" and report["snapshot_id"]
        assert report["server_id"] == f["server_id"]
    for section in ["history", "attempts"]:
        history = await call(
            browser,
            admin,
            "GET",
            "/api/v1/dashboard/notifications/"
            + notification["id"]
            + "/"
            + section
            + "?limit=1&offset=0",
        )
        assert history.status_code == 200, history.text
        assert len(history.json()["items"]) <= 1 and history.json()["limit"] == 1

    response = await call(browser, admin, "GET", "/api/v1/dashboard/overview")
    assert response.status_code == 200, response.text
    value = response.json()
    assert value["active_servers"] >= 1 and value["open_findings"] >= 1
    trend = await call(browser, admin, "GET", "/api/v1/dashboard/overview/trends?days=7")
    assert trend.status_code == 200, trend.text
    assert len(trend.json()["items"]) == 7
    assert sum(i["detected"] for i in trend.json()["items"]) >= 1
    servers = await call(browser, admin, "GET", "/api/v1/dashboard/security/servers")
    assert servers.status_code == 200, servers.text
    own = next(s for s in servers.json()["items"] if s["id"] == str(f["server_id"]))
    assert own["inventory"]["snapshot_id"] and own["open_findings"] >= 1
    assert own["inventory"]["inventory_freshness"] == "not_configured"
    assert "original_data" not in str(own) and "ip_address" not in str(own)
    context = await call(
        browser, admin, ("GET"), f"/api/v1/dashboard/security/findings/{f[('id')]}/context"
    )
    assert context.status_code == 200, context.text
    assert context.json()["snapshot_id"]
    assert context.json()["rule_version"]
    viewer = await actor(browser, ("viewer",))
    denied = await call(browser, viewer, "GET", "/api/v1/dashboard/overview")
    assert denied.status_code == 403
    hidden = await call(
        browser, viewer, ("GET"), f"/api/v1/dashboard/security/servers/{f[('server_id')]}"
    )
    assert hidden.status_code == 404
    empty = await call(browser, viewer, "GET", "/api/v1/dashboard/security/servers")
    assert empty.status_code == 200 and empty.json()["total"] == 0
    analyst = await actor(browser, ("security_analyst",))
    scope = await call(browser, analyst, "GET", "/api/v1/dashboard/overview")
    assert scope.status_code == 200 and scope.json()["active_servers"] == 0
    assert scope.json()["open_findings"] == 0
    with browser.lab.owner() as c:
        c.execute(
            (
                "INSERT INTO security.user_server_access(user_id,se"
                "rver_id,can_read,findings_read) VALUES(%s,%s,true,"
                "false)"
            ),
            (analyst.id, f[("server_id")]),
        )
    limited = await call(browser, analyst, "GET", "/api/v1/dashboard/security/servers")
    assert limited.status_code == 200, limited.text
    assert limited.json()["items"][0]["open_findings"] is None
    with browser.lab.owner() as c:
        c.execute(
            ("UPDATE security.user_server_access SET findings_read=true WHERE user_id=%s"),
            (analyst.id,),
        )
    allowed = await call(browser, analyst, "GET", "/api/v1/dashboard/overview")
    assert allowed.status_code == 200 and allowed.json()["open_findings"] >= 1
    hidden = await call(
        browser, analyst, ("GET"), f"/api/v1/dashboard/security/findings/{uuid4()}/context"
    )
    assert hidden.status_code == 404
    invalid = await call(browser, admin, "GET", "/api/v1/dashboard/overview/trends?days=1000")
    assert invalid.status_code == 422

    from scripts.dashboard.manage import activate, node
    from scripts.security.manage import origin

    e2e_group = await partial_inventory(harness, admin)
    _, mfa_name, mfa_password = await browser.user(admin=True)
    # Browser scenarios assert German labels explicitly; production defaults to English.
    with browser.lab.owner() as c:
        c.execute("UPDATE security.instance_preferences SET default_locale='de',version=version+1")
    activate(browser.lab.config)
    binary = node(browser.lab.config.root)
    env = dict(os.environ)
    env.update(
        PATH=str(binary) + os.pathsep + env.get("PATH", ""),
        PLAYWRIGHT_BROWSERS_PATH=str(browser.lab.config.root / ".runtime/playwright"),
        CVE_E2E_MFA_USER=mfa_name,
        CVE_E2E_MFA_PASSWORD=mfa_password,
        CVE_E2E_URL=origin(browser.lab.config),
        CVE_E2E_COOKIE=admin.cookie,
        CVE_E2E_USER=viewer.name,
        CVE_E2E_PASSWORD=viewer.password,
        CVE_E2E_FINDING=str(f["id"]),
        CVE_E2E_SERVER=str(f["server_id"]),
        CVE_E2E_GROUP=e2e_group,
        CVE_E2E_NOTIFICATION=notification["id"],
    )
    log = browser.lab.config.root / ".runtime/test-reports/phase-20-e2e.log"
    with log.open("w") as output:
        result = subprocess.run(
            [str(binary / "npm"), "--prefix", "services/dashboard", "run", "e2e"],
            env=env,
            cwd=browser.lab.config.root,
            stdout=output,
            stderr=subprocess.STDOUT,
            timeout=240,
            check=False,
        )
    assert result.returncode == 0, log.read_text()


async def test_personal_group_filter_deduplication_and_missing_inventory(browser: Any) -> None:
    from tests.server_administration.integration.conftest import (
        assign_groups,
        create_group,
        create_server,
    )

    admin = await actor(browser)
    servers = [await create_server(browser, admin) for _ in range(3)]
    groups = [await create_group(browser, admin) for _ in range(2)]
    for server in servers:
        changed = await assign_groups(browser, admin, server["id"], [g["id"] for g in groups])
        assert changed.status_code == 200, changed.text
    ids = [server["id"] for server in servers]
    result = await call(
        browser, admin, "GET", "/api/v1/dashboard/security/servers?group_id=" + groups[0]["id"]
    )
    assert result.status_code == 200, result.text
    assert [row["id"] for row in result.json()["items"]] == ids
    assert all(len(row["groups"]) == 2 for row in result.json()["items"])
    assert all(row["primary_group_id"] is None for row in result.json()["items"])
    assert all(
        row["inventory"]["inventory_freshness"] == "missing" for row in result.json()["items"]
    )
    detail = await call(browser, admin, "GET", "/api/v1/dashboard/groups")
    assert detail.status_code == 200
    assert groups[0]["id"] in [g["id"] for g in detail.json()["items"]]
    global_count = await call(browser, admin, "GET", "/api/v1/dashboard/overview")
    assert global_count.json()["active_servers"] >= 3
    assert global_count.json()["inventory"]["missing"] >= 3
    subset = await call(
        browser,
        admin,
        "GET",
        "/api/v1/dashboard/security/servers?limit=1&offset=1&group_id=" + groups[0]["id"],
    )
    assert subset.json()["total"] == 3 and subset.json()["items"][0]["id"] == ids[1]
    viewer = await actor(browser, ("viewer",))
    hidden = await call(
        browser, viewer, "GET", "/api/v1/dashboard/security/servers?group_id=" + groups[0]["id"]
    )
    assert hidden.status_code == 404


async def partial_inventory(harness: Harness, admin: Any) -> str:
    """Real upload/processor pipeline: old valid inventory plus newer failed collection section."""
    import json
    from datetime import UTC, datetime, timedelta

    from cve_findings.contracts import Policy

    from tests.findings.test_api import approve
    from tests.inventory_processor.test_normalization import sample
    from tests.inventory_processor.test_processing import drain
    from tests.inventory_upload.integration.conftest import provision, technical

    browser = harness.browser
    upload = await provision(browser, certificate="client-new")
    value = sample()
    value.update(
        server_id=upload.server["id"],
        captured_at=(datetime.now(UTC) - timedelta(hours=48)).isoformat(),
    )
    first = await technical(browser, upload, json.dumps(value).encode(), certificate="client-new")
    assert first.status_code == 202, first.text
    await drain(browser)
    value.update(
        inventory_id=str(uuid4()),
        captured_at=(datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        collection_status="partial",
    )
    value["services"] = {"status": "failed", "error_code": "collect_failed"}
    latest = await technical(browser, upload, json.dumps(value).encode(), certificate="client-new")
    assert latest.status_code == 202, latest.text
    await drain(browser)
    await approve(harness, admin, Policy(max_snapshot_age_hours=24))
    result = await call(
        browser, admin, "GET", "/api/v1/dashboard/security/servers/" + upload.server["id"]
    )
    assert result.status_code == 200, result.text
    inventory = result.json()["inventory"]
    assert inventory["snapshot_id"] != inventory["latest_snapshot_id"]
    assert inventory["inventory_freshness"] == "stale"
    assert inventory["collection_status"] == "partial"
    overview = await call(browser, admin, "GET", "/api/v1/dashboard/overview")
    assert overview.json()["inventory"]["stale"] >= 1
    assert overview.json()["inventory"]["incomplete"] >= 1

    from tests.server_administration.integration.conftest import assign_groups, create_group

    group = await create_group(browser, admin)
    assigned = await assign_groups(browser, admin, upload.server["id"], [group["id"]])
    assert assigned.status_code == 200, assigned.text
    return str(group["id"])
