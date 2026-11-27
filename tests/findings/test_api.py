"""Real HTTPS ingress, MFA sessions, CSRF, current object scope and immutable commands."""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from cve_findings.contracts import Policy

from tests.authorization.integration.conftest import Actor, actor, fresh
from tests.findings.test_native import Harness, harness
from tests.inventory_upload.integration.conftest import Browser

__all__ = ["harness"]
pytestmark = pytest.mark.findings


async def call(
    browser: Browser,
    person: Actor,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    version: int | None = None,
    *,
    csrf: bool = True,
    reauth: bool = True,
) -> Any:
    if method != "GET" and reauth:
        fresh(browser, person)
    headers = {"cookie": "__Host-cve-session=" + person.cookie}
    from cve_api.auth.sessions import SESSION_COOKIE

    headers["cookie"] = SESSION_COOKIE + "=" + person.cookie
    if csrf:
        headers["x-csrf-token"] = person.csrf
    if version is not None:
        headers["if-match"] = '"' + str(version) + '"'
    return await browser.client.request(
        method, "/api/v1/findings" + path, json=body, headers=headers
    )


def grant(harness: Harness, person: Actor, server: UUID, *, manage: bool = False) -> None:
    with harness.browser.lab.owner() as c:
        c.execute(
            (
                "INSERT INTO security.user_server_access(user_id,server_id,can_read,finding"
                "s_read,findings_manage) VALUES(%s,%s,true,true,%s) ON CONFLICT(user_id,ser"
                "ver_id) DO UPDATE SET findings_read=true,findings_manage=excluded.findings"
                "_manage,version=user_server_access.version+1"
            ),
            (person.id, server, manage),
        )


async def approve(harness: Harness, person: Actor, policy: Policy) -> None:
    response = await call(
        harness.browser,
        person,
        "POST",
        "/policies",
        {
            "label": "test-" + uuid4().hex,
            "reason": "Approved isolated test policy",
            "configuration": policy.model_dump(mode="json"),
        },
    )
    assert response.status_code == 200, response.text
    await harness.drain()


async def test_api_scope_lists_details_counters_and_revocation(harness: Harness) -> None:
    first = await harness.create()
    other = await harness.create()
    viewer = await actor(harness.browser, ("viewer",))
    grant(harness, viewer, first["server_id"])
    response = await call(harness.browser, viewer, "GET", "")
    assert response.status_code == 200, response.text
    total = response.json()["total"]
    assert total >= 1
    assert {r["server_id"] for r in response.json()["items"]} == {str(first["server_id"])}
    assert any(r["id"] == str(first["id"]) for r in response.json()["items"])
    assert (await call(harness.browser, viewer, "GET", "/" + str(other["id"]))).status_code == 404
    summary = await call(harness.browser, viewer, "GET", "/summary")
    assert summary.json()["total"] == total
    for section in [
        "history",
        "episodes",
        "evidence",
        "exceptions",
        "notes",
        "priority",
        "deadlines",
    ]:
        assert (
            await call(harness.browser, viewer, "GET", f"/{other['id']}/{section}")
        ).status_code == 404
        assert (
            await call(harness.browser, viewer, "GET", f"/{first['id']}/{section}")
        ).status_code == 200
    with harness.browser.lab.owner() as c:
        c.execute("DELETE FROM security.user_server_access WHERE user_id=%s", (viewer.id,))
    assert (await call(harness.browser, viewer, "GET", "")).json()["total"] == 0
    assert (await call(harness.browser, viewer, "GET", "/" + str(first["id"]))).status_code == 404


async def test_triage_etag_actor_csrf_and_mass_assignment(harness: Harness) -> None:
    f = await harness.create()
    admin = await actor(harness.browser)
    path = f"/{f['id']}/triage"
    body = {"action": "start", "reason": "Analyst started review"}
    assert (await call(harness.browser, admin, "POST", path, body)).status_code == 428
    assert (
        await call(harness.browser, admin, "POST", path, body, f["version"], csrf=False)
    ).status_code == 403
    bad = await call(
        harness.browser,
        admin,
        "POST",
        path,
        body | {"matching_status": "not_affected", "actor_user_id": str(uuid4())},
        f["version"],
    )
    assert bad.status_code == 422
    response = await call(harness.browser, admin, "POST", path, body, f["version"])
    assert response.status_code == 200, response.text
    assert response.json()["lifecycle_status"] == "in_progress"
    assert response.json()["latest_matching_status"] == "affected"
    assert (await call(harness.browser, admin, "POST", path, body, f["version"])).status_code == 412
    with harness.browser.lab.owner() as c:
        event = c.execute(
            (
                "SELECT * FROM findings.audit_events WHERE finding_id=%s AND kind='triaged'"
                " ORDER BY occurred_at DESC LIMIT 1"
            ),
            (f["id"],),
        ).fetchone()
        assert event["actor_user_id"] == admin.id and event["actor_role"] == "api_security"


async def test_notes_are_plain_text_and_assignment_needs_current_rights(harness: Harness) -> None:
    f = await harness.create()
    admin = await actor(harness.browser)
    viewer = await actor(harness.browser, ("viewer",))
    base = f"/{f['id']}"
    note = "<script>alert('x')</script> ; DROP TABLE inventory.servers;"
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + "/notes",
        {"reason": "Documented evidence", "text": note},
        f["version"],
    )
    assert response.status_code == 200, response.text
    current = response.json()
    assert (await call(harness.browser, admin, "GET", base + "/notes")).json()["items"][0][
        "text"
    ] == note
    assert (
        await call(
            harness.browser,
            admin,
            "POST",
            base + "/assignments",
            {"reason": "Assign reviewer", "assignee_user_id": str(viewer.id)},
            current["version"],
        )
    ).status_code == 409
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + "/assignments",
        {"reason": "Assign authorized reviewer", "assignee_user_id": str(admin.id)},
        current["version"],
    )
    assert response.status_code == 200, response.text
    assert response.json()["assignee_is_eligible"]


async def test_false_positive_close_and_reopen_same_identity(harness: Harness) -> None:
    f = await harness.create()
    admin = await actor(harness.browser)
    base = f"/{f['id']}"
    assert (
        await call(
            harness.browser,
            admin,
            "POST",
            base + "/close",
            {"reason": "Unproven attempted close"},
            f["version"],
        )
    ).status_code == 409
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + "/reviews",
        {
            "reason": "Verified scoped false positive",
            "decision": "confirmed_false_positive",
            "evidence": "Manual test verification for this immutable result",
            "result_id": str(f["latest_matching_result_id"]),
        },
        f["version"],
    )
    assert response.status_code == 200, response.text
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + "/close",
        {"reason": "Authorized false positive disposition"},
        response.json()["version"],
    )
    assert response.status_code == 200, response.text
    assert (
        response.json()["lifecycle_status"] == "closed"
        and response.json()["latest_matching_status"] == "affected"
    )
    harness.publish(f, "affected")
    await harness.drain()
    reopened = harness.get(f["id"])
    assert reopened["id"] == f["id"] and reopened["status"] == "open"
    assert reopened["current_episode_id"] != f["current_episode_id"]
    assert (
        reopened["first_seen_at"] == f["first_seen_at"]
        and reopened["review_state"] == "needs_review"
    )


async def test_unsupported_automatic_resolution_cannot_be_enabled(harness: Harness) -> None:
    admin = await actor(harness.browser)
    with harness.browser.lab.owner() as c:
        before = c.execute("SELECT policy_id FROM findings.active_policy").fetchone()
    response = await call(
        harness.browser,
        admin,
        "POST",
        "/policies",
        {
            "label": "unsupported-" + uuid4().hex,
            "reason": "Unsupported automatic resolution must remain disabled",
            "configuration": Policy(
                automatic_resolution=True, max_snapshot_age_hours=24
            ).model_dump(mode="json"),
        },
    )
    assert response.status_code == 422, response.text
    with harness.browser.lab.owner() as c:
        assert c.execute("SELECT policy_id FROM findings.active_policy").fetchone() == before


async def test_legacy_approved_fix_policy_resolution_and_recurrence(harness: Harness) -> None:
    from scripts.database import manage as db

    f = await harness.create()
    admin = await actor(harness.browser)
    # Model a policy approved before the API disabled this unsupported option.
    # Historical policies and qualified evidence must retain their existing semantics.
    fresh(harness.browser, admin)
    with db.connect(harness.browser.lab.config, "api_security") as c:
        c.execute(
            "SELECT findings.approve_policy(%s,%s,%s::jsonb,%s,%s)",
            (
                UUID(admin.cookie.split(".")[0]),
                "legacy-" + uuid4().hex,
                Policy(automatic_resolution=True, max_snapshot_age_hours=24).model_dump_json(),
                "Previously approved isolated test policy",
                uuid4(),
            ),
        )
    await harness.drain()
    proof = harness.publish(f, "not_affected", coverage=True)
    await harness.drain()
    resolved = harness.get(f["id"])
    assert resolved["status"] == "resolved" and resolved["resolution_result_id"] == proof
    response = await call(
        harness.browser,
        admin,
        "POST",
        f"/{f['id']}/close",
        {"reason": "Current qualified fix verified"},
        resolved["version"],
    )
    assert response.status_code == 200, response.text
    harness.publish(f, "affected")
    await harness.drain()
    assert harness.get(f["id"])["status"] == "open"
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT count(*) n FROM findings.episode_closures WHERE episode_id=%s",
                (f["current_episode_id"],),
            ).fetchone()["n"]
            == 1
        )
    await approve(harness, admin, Policy())


async def test_exception_expiry_and_idempotent_maintenance(harness: Harness) -> None:
    f = await harness.create()
    admin = await actor(harness.browser)
    base = f"/{f['id']}"
    now = datetime.now(UTC)
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + "/exceptions",
        {
            "reason": "Approved scoped test interval",
            "risk_context": "Known isolated test risk",
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(seconds=3)).isoformat(),
            "scope": "episode",
        },
        f["version"],
    )
    assert response.status_code == 200, response.text
    exceptions = await call(harness.browser, admin, "GET", base + "/exceptions")
    eid = exceptions.json()["items"][0]["id"]
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + f"/exceptions/{eid}/approve",
        {"reason": "Authorized temporary acceptance"},
        response.json()["version"],
    )
    assert response.status_code == 200, response.text
    assert (
        response.json()["has_active_exception"]
        and response.json()["latest_matching_status"] == "affected"
    )
    await asyncio.sleep(3.1)
    assert not harness.get(f["id"])["has_active_exception"]
    for _ in range(2):
        harness.enqueue("check_exceptions")
        await harness.drain()
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM findings.exception_decisions WHERE exception_id"
                    "=%s AND decision='expired'"
                ),
                (eid,),
            ).fetchone()["n"]
            == 1
        )
    assert harness.get(f["id"])["status"] == "open"


async def test_viewer_and_user_admin_cannot_mutate_or_manage_policy(harness: Harness) -> None:
    f = await harness.create()
    for role in ["viewer", "security_analyst", "user_admin"]:
        person = await actor(harness.browser, (role,))
        grant(harness, person, f["server_id"], manage=True)
        response = await call(
            harness.browser,
            person,
            "POST",
            f"/{f['id']}/triage",
            {"action": "start", "reason": "Attempted unauthorized change"},
            f["version"],
        )
        assert response.status_code == 403
        assert (
            await call(
                harness.browser,
                person,
                "POST",
                "/policies",
                {"label": "forbidden", "reason": "Unapproved policy change", "configuration": {}},
            )
        ).status_code == 403


async def test_filter_sorting_and_archived_history(harness: Harness) -> None:
    f = await harness.create()
    admin = await actor(harness.browser)
    assert (
        await call(harness.browser, admin, "GET", "?sort=priority;DROP%20TABLE%20findings.findings")
    ).status_code == 422
    response = await call(
        harness.browser,
        admin,
        "GET",
        f"?server_id={f['server_id']}&cve_id={f['cve_id']}&lifecycle=open&limit=1",
    )
    assert response.status_code == 200 and response.json()["total"] == 1
    with harness.browser.lab.owner() as c:
        c.execute(
            (
                "UPDATE inventory.servers SET status='archived',archived_at=clock_timestamp"
                "(),version=version+1 WHERE id=%s"
            ),
            (f["server_id"],),
        )
    assert (await call(harness.browser, admin, "GET", f"/{f['id']}")).status_code == 200
    assert harness.get(f["id"])["status"] == "open"
    assert (
        await call(
            harness.browser,
            admin,
            "POST",
            f"/{f['id']}/triage",
            {"action": "start", "reason": "Archived object modification"},
            harness.get(f["id"])["version"],
        )
    ).status_code == 403


async def test_risk_only_matching_basis_does_not_reopen(harness: Harness) -> None:
    f = await harness.create()
    admin = await actor(harness.browser)
    base = f"/{f['id']}"
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + "/reviews",
        {
            "reason": "Verified original technical scope",
            "decision": "confirmed_false_positive",
            "evidence": "Scope review of unchanged component evidence",
            "result_id": str(f["latest_matching_result_id"]),
        },
        f["version"],
    )
    assert response.status_code == 200, response.text
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + "/close",
        {"reason": "Authorized scoped disposition"},
        response.json()["version"],
    )
    assert response.status_code == 200, response.text
    harness.publish(f, "affected", technical_change=False)
    await harness.drain()
    updated = harness.get(f["id"])
    assert (
        updated["status"] == "closed" and updated["current_episode_id"] == f["current_episode_id"]
    )


async def test_sla_deadline_history_and_once_only_escalation(harness: Harness) -> None:
    from scripts.database import manage as db

    f = await harness.create()
    admin = await actor(harness.browser)
    await approve(harness, admin, Policy(deadlines_hours={"unrated": 1}, deadline_warning_hours=1))
    current = harness.get(f["id"])
    assert current["due_at"] is not None
    first_due = current["due_at"]
    await approve(harness, admin, Policy(deadlines_hours={"unrated": 2}, deadline_warning_hours=1))
    assert harness.get(f["id"])["due_at"] == first_due
    # Isolated fixture models an elapsed approved deadline; no runtime clock controls exist.
    with db.connect(harness.browser.lab.config, "findings_writer") as c:
        past = uuid4()
        c.execute(
            (
                "INSERT INTO findings.deadlines(id,finding_id,episode_id,policy_id,due_at,ancho"
                "r_at,priority,reason) SELECT %s,f.id,f.current_episode_id,a.policy_id,clock_ti"
                "mestamp()-interval '1 second',clock_timestamp()-interval '1 hour','unrated','f"
                "ixture_elapsed_time' FROM findings.findings f CROSS JOIN findings.active_polic"
                "y a WHERE f.id=%s"
            ),
            (past, f["id"]),
        )
        c.execute(
            ("UPDATE findings.findings SET current_deadline_id=%s,version=version+1 WHERE id=%s"),
            (past, f["id"]),
        )
        c.execute(
            (
                "SELECT findings.record_change(%s,'updated','{}','fixture_elapsed_time',%s,NULL"
                ",NULL)"
            ),
            (f["id"], uuid4()),
        )
    for _ in range(2):
        harness.enqueue("check_deadlines")
        await harness.drain()
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM findings.escalations WHERE deadline_id=%s AND kind='ove"
                    "rdue'"
                ),
                (past,),
            ).fetchone()["n"]
            == 1
        )
        assert (
            c.execute(
                "SELECT count(*) n FROM findings.deadlines WHERE finding_id=%s", (f["id"],)
            ).fetchone()["n"]
            >= 2
        )
    assert harness.get(f["id"])["is_overdue"] and harness.get(f["id"])["status"] == "open"
    await approve(harness, admin, Policy())


@pytest.mark.parametrize("change", ["closed", "postponed"])
async def test_deadline_selection_rechecks_a_concurrent_commit(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    from types import SimpleNamespace

    from cve_common.database.transactions import transaction
    from cve_findings import service
    from cve_findings.contracts import Request
    from cve_findings.repository import rows as original

    from scripts.database import manage as db

    finding = await harness.create()
    admin = await actor(harness.browser)
    await approve(harness, admin, Policy(deadlines_hours={"unrated": 1}))
    if change == "closed":
        reviewed = await call(
            harness.browser,
            admin,
            "POST",
            f"/{finding['id']}/reviews",
            {
                "reason": "Verified before concurrent close",
                "decision": "confirmed_false_positive",
                "evidence": "Isolated concurrency fixture",
                "result_id": str(finding["latest_matching_result_id"]),
            },
            harness.get(finding["id"])["version"],
        )
        assert reviewed.status_code == 200, reviewed.text

    def deadline(hours: int) -> None:
        with db.connect(harness.browser.lab.config, "findings_writer") as c:
            identity = uuid4()
            c.execute(
                "INSERT INTO findings.deadlines"
                "(id,finding_id,episode_id,policy_id,due_at,anchor_at,priority,reason) "
                "SELECT %s,f.id,f.current_episode_id,a.policy_id,"
                "clock_timestamp()+make_interval(hours=>%s),clock_timestamp(),"
                "'unrated','fixture_concurrent_commit' FROM findings.findings f "
                "CROSS JOIN findings.active_policy a WHERE f.id=%s",
                (identity, hours, finding["id"]),
            )
            c.execute(
                "UPDATE findings.findings SET current_deadline_id=%s,version=version+1 WHERE id=%s",
                (identity, finding["id"]),
            )
            c.execute(
                "SELECT findings.record_change(%s,'updated','{}',"
                "'fixture_concurrent_commit',%s,NULL,NULL)",
                (finding["id"], uuid4()),
            )

    deadline(-1)
    interleaved = False

    async def selected(*args: Any, **kwargs: Any) -> Any:
        nonlocal interleaved
        values = await original(*args, **kwargs)
        assert any(row["id"] == finding["id"] for row in values)
        if change == "closed":
            result = await call(
                harness.browser,
                admin,
                "POST",
                f"/{finding['id']}/close",
                {"reason": "Concurrent authorized close"},
                harness.get(finding["id"])["version"],
            )
            assert result.status_code == 200, result.text
        else:
            deadline(48)
        interleaved = True
        return values

    monkeypatch.setattr(service, "rows", selected)
    context: Any = SimpleNamespace(job=SimpleNamespace(correlation_id=uuid4()))
    async with transaction(harness.database) as session:
        await harness.service.deadlines(session, context, Request())
    assert interleaved
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                "SELECT count(*) n FROM findings.escalations e JOIN findings.deadlines d "
                "ON d.id=e.deadline_id WHERE d.finding_id=%s",
                (finding["id"],),
            ).fetchone()["n"]
            == 0
        )


async def test_exception_revocation_and_new_basis_scope(harness: Harness) -> None:
    f = await harness.create()
    admin = await actor(harness.browser)
    base = f"/{f['id']}"
    now = datetime.now(UTC)
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + "/exceptions",
        {
            "reason": "Basis scoped risk request",
            "risk_context": "Verified temporary operating context",
            "valid_from": now.isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
            "scope": "basis",
        },
        f["version"],
    )
    assert response.status_code == 200, response.text
    eid = (await call(harness.browser, admin, "GET", base + "/exceptions")).json()["items"][0]["id"]
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + f"/exceptions/{eid}/approve",
        {"reason": "Authorized bounded acceptance"},
        response.json()["version"],
    )
    assert response.status_code == 200, response.text
    assert response.json()["has_active_exception"]
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + f"/exceptions/{eid}/revoke",
        {"reason": "Risk acceptance withdrawn"},
        response.json()["version"],
    )
    assert response.status_code == 200 and not response.json()["has_active_exception"]
    assert response.json()["latest_matching_status"] == "affected"
    assert (
        await call(
            harness.browser,
            admin,
            "POST",
            base + f"/exceptions/{eid}/approve",
            {"reason": "Forbidden silent extension"},
            response.json()["version"],
        )
    ).status_code == 409


async def test_actual_https_gate_and_authenticated_finding(harness: Harness) -> None:
    from cve_api.auth.sessions import SESSION_COOKIE

    from scripts.infrastructure.manage import run

    f = await harness.create()
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
        "--write-out",
        "\n%{http_code}",
        "--config",
        "-",
        f"https://{host}:{port}/api/v1/findings/{f['id']}",
    ]
    anonymous = await asyncio.to_thread(run, args, input="")
    assert anonymous.stdout.rsplit("\n", 1)[1] == "401"
    authenticated = await asyncio.to_thread(
        run, args, input=f'header = "Cookie: {SESSION_COOKIE}={admin.cookie}"\n'
    )
    body, status = authenticated.stdout.rsplit("\n", 1)
    assert status == "200"
    import json

    assert json.loads(body)["id"] == str(f["id"])


async def test_stale_proof_cannot_be_manually_closed(harness: Harness) -> None:
    f = await harness.create(age_hours=2)
    admin = await actor(harness.browser)
    base = f"/{f['id']}"
    await approve(harness, admin, Policy(max_snapshot_age_hours=1))
    current = harness.get(f["id"])
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + "/reviews",
        {
            "reason": "Review historical scoped evidence",
            "decision": "confirmed_false_positive",
            "evidence": "Historical review does not refresh snapshot age",
            "result_id": str(f["latest_matching_result_id"]),
        },
        current["version"],
    )
    assert response.status_code == 200, response.text
    response = await call(
        harness.browser,
        admin,
        "POST",
        base + "/close",
        {"reason": "Attempt to close with stale evidence"},
        response.json()["version"],
    )
    assert response.status_code == 409
    assert harness.get(f["id"])["status"] == "open"
    await approve(harness, admin, Policy())
