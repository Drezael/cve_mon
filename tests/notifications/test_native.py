"""Native source, identities, deduplication, leases, delivery and permission boundaries."""

import asyncio
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from cve_common.database.engine import Database
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import Registry
from cve_common.jobs.repository import JobRepository
from cve_notification.contracts import Request
from cve_notification.service import Service

from tests.findings.test_native import Harness as Findings
from tests.findings.test_native import harness as finding_harness
from tests.inventory_upload.integration.conftest import Browser

__all__ = ["finding_harness"]
pytestmark = pytest.mark.notifications


class Harness:
    def __init__(self, browser: Browser) -> None:
        self.browser = browser
        self.findings = Findings(browser)
        self.database = Database(
            browser.lab.database("notification").model_copy(update={"statement_timeout_ms": 30000})
        )
        self.database.open()
        self.rule_id = None
        self.service = Service(self.database)
        # Native decision tests do not own an n8n runtime. Its real orchestration is
        # exercised by test_container; never drain leftover orchestration jobs here.
        registry = Registry()
        for name in ["notifications.consume_event", "notifications.maintenance"]:
            registry.register(self.service.registry().get(name, 1))
        self.jobs = JobRepository(self.database, registry)

    async def drain(self) -> None:
        for _ in range(2000):
            job = await self.jobs.claim(uuid4(), 30)
            if job is None:
                from cve_common.database.transactions import transaction
                from cve_notification.reports import maintain

                async with transaction(self.database) as session:
                    await maintain(session, uuid4())
                return
            ctx = ExecutionContext(
                self.jobs, job, self.jobs.registry.get(job.job_type, 1), asyncio.Event()
            )
            await self.service.handle(ctx, Request.model_validate(job.payload))
        raise AssertionError("unbounded jobs")

    def enable(self, **config: Any) -> None:
        import json

        from cve_notification.contracts import Rule

        rule = Rule.model_validate(
            {"recipients": "authorized", "minimum_priority": "unrated", **config}
        )
        assert self.browser.lab.config.project.startswith("cve-db-test-")
        with self.browser.lab.owner() as c:
            c.execute(
                "INSERT INTO automation.notification_rules(rule_key"
                ",version,config,reason) SELECT rule_key,version+1,"
                "config||'{\"enabled\":false}'::jsonb,'Isolated test "
                "policy transition' FROM (SELECT DISTINCT ON(rule_k"
                "ey) * FROM automation.notification_rules ORDER BY "
                "rule_key,version DESC) r WHERE coalesce((config->>"
                "'enabled')::boolean,false)"
            )
            value = c.execute(
                (
                    "INSERT INTO automation.notification_rules(rule_key"
                    ",version,config,reason) VALUES(%s,(SELECT coalesce(max(version),0)+1 "
                    "FROM automation.notification_rules WHERE rule_key="
                    "'00000000-0000-0000-0000-000000000067'),%s::jsonb,%s) "
                    "RETURNING id"
                ),
                (
                    UUID("00000000-0000-0000-0000-000000000067"),
                    json.dumps(rule.model_dump(mode="json")),
                    "Isolated approved test rule",
                ),
            ).fetchone()
            self.rule_id = value["id"]

    def intents(self) -> list[dict[str, Any]]:
        with self.browser.lab.owner() as c:
            return [
                dict(r)
                for r in c.execute(
                    (
                        "SELECT n.*,(SELECT srv.server_id FROM automation.mail_reports r "
                        "JOIN automation.mail_report_servers srv ON srv.report_id=r.id "
                        "WHERE r.notification_id=n.id LIMIT 1) AS reported_server_id "
                        "FROM automation.notification_intents n WHER"
                        "E rule_id=%s ORDER BY created_at,id"
                    ),
                    (self.rule_id,),
                ).fetchall()
            ]


@pytest.fixture
async def harness(browser: Browser, finding_harness: Findings) -> Any:
    value = Harness(browser)
    await value.findings.database.close()
    await value.findings.matcher.database.close()
    value.findings = finding_harness
    try:
        yield value
    finally:
        await value.database.close()


async def test_real_finding_event_creates_deduplicated_intents(harness: Harness) -> None:
    harness.enable()
    f = await harness.findings.create()
    await harness.drain()
    values = harness.intents()
    assert values
    assert any(v["reported_server_id"] == f["server_id"] for v in values)
    with harness.browser.lab.owner() as c:
        assert (
            c.execute("SELECT count(*) n FROM automation.notification_event_receipts").fetchone()[
                "n"
            ]
            > 0
        )
    await harness.drain()
    assert harness.intents() == values


async def run_for(harness: Harness, notification: dict[str, Any]) -> tuple[Any, Any]:
    from cve_common.database.transactions import transaction
    from cve_notification.repository import one

    async with transaction(harness.database) as s:
        run = await one(
            s,
            (
                "INSERT INTO automation.notification_workflow_runs("
                "notification_id,workflow,workflow_version,request_"
                "id,state,expires_at) VALUES(:id,'dispatch',1,:requ"
                "est,'requested',clock_timestamp()+interval '5 minu"
                "tes') RETURNING id,request_id"
            ),
            id=notification["id"],
            request=uuid4(),
        )
        assert run
        return run["id"], run["request_id"]


class FakeRelay:
    def __init__(self, status: str = "relay_accepted") -> None:
        self.calls = 0
        self.status = status
        self.messages: list[Any] = []

    def submit(self, message: Any) -> Any:
        from cve_notification.smtp import Outcome

        self.calls += 1
        self.messages.append(message)
        return Outcome(
            cast(Any, self.status),
            "synthetic_native_transport",
            "TESTQUEUE123" if self.status == "relay_accepted" else None,
        )


async def dispatcher(harness: Harness, relay: FakeRelay) -> Any:
    from typing import cast

    from cve_notification.dispatch import Dispatch
    from cve_notification.smtp import Adapter

    return Dispatch(
        harness.database,
        cast(Adapter, relay),
        sender="security@example.test",
        base="https://dashboard.example.test",
        relay_instance="isolated-relay",
    )


async def ready(harness: Harness, **rule: Any) -> dict[str, Any]:
    harness.enable(**rule)
    f = await harness.findings.create()
    await harness.drain()
    return next(
        n
        for n in harness.intents()
        if n["reported_server_id"] == f["server_id"] and n["status"] == "ready"
    )


async def test_smtp_claim_fence_idempotency_and_accepted_history(harness: Harness) -> None:
    n = await ready(harness)
    relay = FakeRelay()
    d = await dispatcher(harness, relay)
    run, request = await run_for(harness, n)
    claims = await asyncio.gather(d.claim(run, request), d.claim(run, request))
    assert sum(bool(c["claimed"]) for c in claims) == 1
    await asyncio.gather(d.execute(run, request), d.execute(run, request))
    await d.execute(run, request)
    assert relay.calls == 1
    with harness.browser.lab.owner() as c:
        current = c.execute(
            "SELECT * FROM automation.notification_intents WHERE id=%s", (n["id"],)
        ).fetchone()
        assert current["status"] == "relay_accepted"
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM automation.notification_del"
                    "ivery_attempts WHERE notification_id=%s"
                ),
                (n["id"],),
            ).fetchone()["n"]
            == 1
        )
        result = c.execute(
            (
                "SELECT r.* FROM automation.notification_delivery_r"
                "esults r JOIN automation.notification_delivery_att"
                "empts a ON a.id=r.attempt_id WHERE a.notification_"
                "id=%s"
            ),
            (n["id"],),
        ).fetchone()
        assert result["queue_id"] == "TESTQUEUE123" and result["relay_instance"] == "isolated-relay"
        assert (
            c.execute(
                "SELECT count(*) n FROM automation.notification_history WHERE notification_id=%s",
                (n["id"],),
            ).fetchone()["n"]
            == current["version"]
        )


@pytest.mark.parametrize(
    "status", ["retryable_failure", "permanent_failure", "submission_uncertain"]
)
async def test_delivery_outcomes_and_no_blind_retry(harness: Harness, status: str) -> None:
    n = await ready(harness)
    relay = FakeRelay(status)
    d = await dispatcher(harness, relay)
    run, request = await run_for(harness, n)
    assert (await d.claim(run, request))["claimed"]
    await d.execute(run, request)
    await d.execute(run, request)
    assert relay.calls == 1
    with harness.browser.lab.owner() as c:
        current = c.execute(
            "SELECT * FROM automation.notification_intents WHERE id=%s", (n["id"],)
        ).fetchone()
        assert current["status"] == status
        if status == "retryable_failure":
            assert current["scheduled_at"] > current["created_at"]


async def test_recipient_disabled_after_preparation_is_not_sent(harness: Harness) -> None:
    n = await ready(harness)
    relay = FakeRelay()
    d = await dispatcher(harness, relay)
    run, request = await run_for(harness, n)
    await d.claim(run, request)
    with harness.browser.lab.owner() as c:
        # Multiple isolated administrators exist; revoke this recipient before sending.
        old = c.execute(
            "SELECT status FROM security.users WHERE id=%s", (n["recipient_user_id"],)
        ).fetchone()["status"]
        c.execute(
            "UPDATE security.users SET status=%s,version=version+1 WHERE id=%s",
            ("disabled", n["recipient_user_id"]),
        )
    try:
        await d.execute(run, request)
        assert relay.calls == 0
        with harness.browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT status FROM automation.notification_intents WHERE id=%s", (n["id"],)
                ).fetchone()["status"]
                == "suppressed"
            )
    finally:
        with harness.browser.lab.owner() as c:
            c.execute(
                "UPDATE security.users SET status=%s,version=version+1 WHERE id=%s",
                (old, n["recipient_user_id"]),
            )


@pytest.mark.parametrize(
    "table",
    [
        "inventory.servers",
        "inventory.server_groups",
        "inventory.server_group_memberships",
        "dashboard.group_order",
        "dashboard.server_order",
        "security.users",
        "security.user_server_access",
        "security.api_tokens",
        "cve.source_records",
        "cve.enrichment_revisions",
        "matching.result_revisions",
        "findings.findings",
    ],
)
async def test_notification_role_cannot_change_sources(harness: Harness, table: str) -> None:
    import psycopg

    from scripts.database import manage

    with (
        manage.connect(harness.browser.lab.config, "notification") as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("DELETE FROM " + table + " WHERE false")


@pytest.mark.parametrize(
    "table",
    [
        "notification_rules",
        "notification_templates",
        "notification_delivery_attempts",
        "notification_delivery_results",
        "notification_history",
        "notification_audit",
        "notification_event_receipts",
    ],
)
async def test_history_and_configuration_not_directly_mutable(harness: Harness, table: str) -> None:
    import psycopg

    from scripts.database import manage

    with (
        manage.connect(harness.browser.lab.config, "notification") as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("DELETE FROM automation." + table + " WHERE false")


async def test_n8n_cannot_connect_to_domain_database(harness: Harness) -> None:
    import psycopg

    from scripts.database import manage

    with (
        pytest.raises(psycopg.OperationalError),
        manage.connect(harness.browser.lab.config, "n8n_app", "cve_monitoring"),
    ):
        pass


async def test_digest_window_idempotency_and_single_recipient_content(harness: Harness) -> None:
    from datetime import UTC, datetime

    from cve_common.database.transactions import transaction
    from cve_notification.repository import change

    harness.enable(mode="digest")
    f = await harness.findings.create()
    await harness.drain()
    values = [n for n in harness.intents() if n["reported_server_id"] == f["server_id"]]
    parent = next(n for n in values if n["kind"] == "digest")
    children = [n for n in values if n["digest_id"] == parent["id"]]
    assert not children and len(values) == 1
    assert parent["window_start"] is None and parent["window_end"] is None
    before = len(harness.intents())
    await harness.drain()
    assert len(harness.intents()) == before
    async with transaction(harness.database) as s:
        await change(s, parent, "ready", "isolated_elapsed_window", due=datetime.now(UTC))
    relay = FakeRelay()
    d = await dispatcher(harness, relay)
    run, request = await run_for(harness, parent)
    await d.claim(run, request)
    await d.execute(run, request)
    await d.execute(run, request)
    assert relay.calls == 1
    assert f["cve_id"] in relay.messages[0].get_body(preferencelist=("plain",)).get_content()


async def test_persistent_rate_limit_defers_second_submit(harness: Harness) -> None:
    n = await ready(harness, rate_per_hour=1)
    second_finding = await harness.findings.create()
    with harness.browser.lab.owner() as session:
        session.execute(
            "UPDATE inventory.servers SET created_by=%s,version=version+1 WHERE id=%s",
            (n["recipient_user_id"], second_finding["server_id"]),
        )
    await harness.drain()
    candidates = [
        r
        for r in harness.intents()
        if r["recipient_user_id"] == n["recipient_user_id"] and r["status"] == "ready"
    ]
    assert len(candidates) >= 2
    relay = FakeRelay()
    d = await dispatcher(harness, relay)
    for candidate in candidates[:2]:
        run, request = await run_for(harness, candidate)
        await d.claim(run, request)
        await d.execute(run, request)
    assert relay.calls == 1
    with harness.browser.lab.owner() as c:
        second = c.execute(
            "SELECT status,reason FROM automation.notification_intents WHERE id=%s",
            (candidates[1]["id"],),
        ).fetchone()
        assert second["status"] == "deferred" and second["reason"] == "quiet_time_or_rate_limit"


async def test_lost_job_lease_rolls_back_all_decisions(harness: Harness) -> None:
    from cve_common.jobs.errors import LeaseLost

    harness.enable()
    await harness.findings.create()
    job = await harness.jobs.claim(uuid4(), 0.2)
    assert job
    context = ExecutionContext(
        harness.jobs, job, harness.jobs.registry.get(job.job_type, 1), asyncio.Event()
    )
    await asyncio.sleep(0.3)
    with pytest.raises(LeaseLost):
        await harness.service.handle(context, Request.model_validate(job.payload))
    assert not harness.intents()
    await harness.jobs.recover()


async def test_one_server_report_does_not_fan_out_to_authorized_users(
    harness: Harness, record_property: Any
) -> None:
    import time

    harness.enable()
    f = await harness.findings.create()
    with harness.browser.lab.owner() as c:
        role = c.execute("SELECT id FROM security.roles WHERE code='viewer'").fetchone()["id"]
        for _ in range(100):
            identity = uuid4()
            name = "notify-" + identity.hex[:16]
            c.execute(
                (
                    "INSERT INTO security.users(id,username,display_nam"
                    "e,email,status) VALUES(%s,%s,%s,%s,'active')"
                ),
                (identity, name, name, name + "@example.test"),
            )
            c.execute(
                "INSERT INTO security.user_roles(user_id,role_id) VALUES(%s,%s)", (identity, role)
            )
            c.execute(
                (
                    "INSERT INTO security.user_server_access(user_id,se"
                    "rver_id,can_read,findings_read) VALUES(%s,%s,true,"
                    "true)"
                ),
                (identity, f["server_id"]),
            )
    start = time.monotonic()
    await harness.drain()
    elapsed = time.monotonic() - start
    record_property("hundred_recipients_seconds", elapsed)
    assert elapsed < 60
    values = [
        n
        for n in harness.intents()
        if n["reported_server_id"] == f["server_id"] and n["status"] == "ready"
    ]
    assert len(values) == 1
    assert values[0]["kind"] == "digest"


async def test_exception_approaching_is_durable_once_without_finding_mutation(
    harness: Harness,
) -> None:
    from datetime import UTC, datetime, timedelta

    from cve_common.database.transactions import transaction

    from tests.authorization.integration.conftest import actor
    from tests.findings.test_api import call

    harness.enable()
    f = await harness.findings.create()
    admin = await actor(harness.browser)
    now = datetime.now(UTC)
    result = await call(
        harness.browser,
        admin,
        "POST",
        f"/{f['id']}/exceptions",
        {
            "reason": "Isolated approved interval",
            "risk_context": "Synthetic warning test",
            "scope": "episode",
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(hours=1)).isoformat(),
        },
        f["version"],
    )
    assert result.status_code == 200, result.text
    exceptions = await call(harness.browser, admin, "GET", f"/{f['id']}/exceptions")
    eid = exceptions.json()["items"][0]["id"]
    approved = await call(
        harness.browser,
        admin,
        "POST",
        f"/{f['id']}/exceptions/{eid}/approve",
        {"reason": "Explicit isolated approval"},
        result.json()["version"],
    )
    assert approved.status_code == 200, approved.text
    before = harness.findings.get(f["id"])
    for _ in range(2):
        async with transaction(harness.database) as s:
            await harness.service.exception_warnings(s, uuid4())
    await harness.drain()
    with harness.browser.lab.owner() as c:
        assert (
            c.execute(
                (
                    "SELECT count(*) n FROM automation.notification_exc"
                    "eption_warnings WHERE exception_id=%s"
                ),
                (eid,),
            ).fetchone()["n"]
            == 1
        )
    after = harness.findings.get(f["id"])
    assert all(
        before[k] == after[k]
        for k in ["version", "status", "latest_matching_result_id", "current_episode_id"]
    )
    assert all(n["kind"] == "digest" for n in harness.intents())


async def test_personal_recipients_and_transport_are_used_at_dispatch(
    harness: Harness, tmp_path: Any
) -> None:
    import json

    n = await ready(harness)
    owner = str(n["recipient_user_id"])
    config = {
        "enabled": True,
        "mode": "custom",
        "host": "smtp.personal.example.org",
        "port": 587,
        "sender": "mine@example.org",
        "recipients": ["one@example.org", "two@example.org"],
    }
    with harness.browser.lab.owner() as s:
        s.execute(
            "INSERT INTO automation.smtp_configs(id,owner_id,requested_by,version,"
            "configuration,credentials,key_id,state) VALUES(%s,%s,%s,1,%s,"
            "decode(repeat('01',40),'hex'),'test','applied')",
            (uuid4(), owner, owner, json.dumps(config)),
        )
    envelope = "user" + owner.replace("-", "") + "@cve-routing.invalid"
    (tmp_path / "smtp-delivery.json").write_text(
        json.dumps(
            {
                owner: {"sender": config["sender"], "envelope_sender": envelope},
                "system": {
                    "sender": "central@example.org",
                    "envelope_sender": "system@cve-routing.invalid",
                },
            }
        )
    )

    class PersonalRelay(FakeRelay):
        def __init__(self) -> None:
            super().__init__()
            self.options: dict[str, Any] = {}

        def submit(self, message: Any, **kwargs: Any) -> Any:
            self.options = kwargs
            return super().submit(message)

    relay = PersonalRelay()
    d = await dispatcher(harness, relay)
    d.configuration_dir = tmp_path
    run, request = await run_for(harness, n)
    assert (await d.claim(run, request))["claimed"]
    assert (await d.execute(run, request))["status"] == "relay_accepted"
    assert relay.calls == 1 and relay.options == {
        "envelope_sender": envelope,
        "recipients": config["recipients"],
    }
    assert relay.messages[0]["From"] == "mine@example.org"
    assert str(relay.messages[0]["To"]) == "one@example.org, two@example.org"
    # Removing the personal route cannot silently send through the available system profile.
    from cve_notification.mail_settings import route

    (tmp_path / "smtp-delivery.json").write_text(
        json.dumps(
            {
                "system": {
                    "sender": "central@example.org",
                    "envelope_sender": "system@cve-routing.invalid",
                }
            }
        )
    )
    assert route(tmp_path, owner, config) is None


async def test_new_finding_notifies_only_owner_after_risk_refresh_once(harness: Harness) -> None:
    from cve_common.database.transactions import transaction
    from cve_findings.repository import record
    from sqlalchemy import text

    harness.enable(recipients="server_owner", event_types=["created"])
    finding = await harness.findings.create()
    with harness.browser.lab.owner() as s:
        server = s.execute(
            "SELECT created_by FROM inventory.servers WHERE id=%s", (finding["server_id"],)
        ).fetchone()
        assert server and server["created_by"]
    async with transaction(harness.findings.database) as s:
        await s.execute(
            text("UPDATE findings.findings SET version=version+1 WHERE id=:id"),
            {"id": finding["id"]},
        )
        await record(s, finding["id"], "updated", finding, "risk_evidence_updated", uuid4())
    await harness.drain()
    intents = [n for n in harness.intents() if n["reported_server_id"] == finding["server_id"]]
    assert len(intents) == 1 and intents[0]["recipient_user_id"] == server["created_by"]
    assert intents[0]["kind"] == "digest" and intents[0]["status"] == "ready"
    await harness.drain()
    assert [
        n for n in harness.intents() if n["reported_server_id"] == finding["server_id"]
    ] == intents
    relay = FakeRelay()
    delivery = await dispatcher(harness, relay)
    run, request = await run_for(harness, intents[0])
    assert (await delivery.claim(run, request))["claimed"]
    await delivery.execute(run, request)
    await delivery.execute(run, request)
    assert relay.calls == 1
    assert finding["cve_id"] in relay.messages[0].get_body(preferencelist=("plain",)).get_content()


async def test_owner_notification_rechecks_owner_before_delivery(harness: Harness) -> None:
    harness.enable(recipients="server_owner", event_types=["created"])
    finding = await harness.findings.create()
    await harness.drain()
    intent = next(n for n in harness.intents() if n["reported_server_id"] == finding["server_id"])
    relay = FakeRelay()
    delivery = await dispatcher(harness, relay)
    run, request = await run_for(harness, intent)
    assert (await delivery.claim(run, request))["claimed"]
    with harness.browser.lab.owner() as s:
        s.execute(
            "UPDATE inventory.servers SET created_by=NULL,version=version+1 WHERE id=%s",
            (finding["server_id"],),
        )
    await delivery.execute(run, request)
    assert relay.calls == 0
    with harness.browser.lab.owner() as s:
        row = s.execute(
            "SELECT status,reason FROM automation.notification_intents WHERE id=%s", (intent["id"],)
        ).fetchone()
        assert row and row["status"] == "suppressed" and row["reason"] == "recipient_not_authorized"


async def test_two_cves_wait_for_complete_scan_and_share_one_mail(harness: Harness) -> None:
    from cve_common.database.transactions import transaction
    from cve_matcher.service import index_revision

    harness.enable()
    matcher = harness.findings.matcher
    snapshot = await matcher.snapshot()
    first, a = matcher.seed()
    second, b = matcher.seed()
    async with transaction(matcher.database) as s:
        await index_revision(s, a)
        await index_revision(s, b)
    matcher.enqueue("evaluate_snapshot", snapshot_id=snapshot)
    await matcher.drain()
    # One finding has been published, but its peer is still waiting in the
    # durable findings queue: no mail may be prepared at this point.
    assert await harness.findings.execute() is not None
    await harness.drain()
    assert not harness.intents()
    await harness.findings.drain()
    await harness.drain()
    values = harness.intents()
    assert len(values) == 1
    relay = FakeRelay()
    delivery = await dispatcher(harness, relay)
    run, request = await run_for(harness, values[0])
    assert (await delivery.claim(run, request))["claimed"]
    await delivery.execute(run, request)
    assert relay.calls == 1
    body = relay.messages[0].get_body(preferencelist=("plain",)).get_content()
    assert first in body and second in body and "Server:" in body
    matcher.enqueue("evaluate_snapshot", snapshot_id=snapshot)
    await matcher.drain()
    await harness.findings.drain()
    await harness.drain()
    assert len(harness.intents()) == 1
