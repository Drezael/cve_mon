"""Real PostgreSQL observations, transactions, maintenance security and fail-closed reads."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from cve_api.status.collector import Collector
from cve_api.status.models import Observation, Settings, State
from cve_common.database.transactions import transaction

from scripts.database.manage import secret_file
from tests.authorization.integration.conftest import actor
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.status_integration


def collector(browser: Browser) -> Collector:
    cfg = browser.lab.config
    db = browser.service.settings.database.model_copy(
        update={"username": "status_probe", "password_file": secret_file(cfg, "status_probe")}
    )
    base = cfg.root / ".runtime/services" / cfg.project
    value = Collector(
        Settings(
            app_env="test",
            database=db,
            reports_dir=cfg.root / ".runtime/status" / cfg.project,
            dashboard_ca=base / "dashboard-ca.crt",
            probe_key_file=base / "status-probe.key",
            dashboard_host=cfg.values["DASHBOARD_DOMAIN"],
        )
    )
    value.database.open()
    return value


def samples(state: State = "healthy") -> list[Observation]:
    from cve_api.status.catalog import CATALOG

    return [
        Observation(
            service_id=key,
            check_id="readiness",
            checked_at=datetime.now(UTC),
            result=state if key == "api" else "healthy",
            duration_ms=1,
            reason_code="CHECK_CONFIRMED",
        )
        for key in CATALOG
    ]


async def store(value: Collector, state: State = "healthy") -> None:
    async with transaction(value.database) as s:
        await value.persist(s, samples(state), datetime.now(UTC) - timedelta(seconds=1), uuid4())


async def call(
    browser: Browser,
    person: Any,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    version: int | None = None,
) -> Any:
    headers = {"cookie": "__Host-cve-session=" + person.cookie, "x-csrf-token": person.csrf}
    if version is not None:
        headers["if-match"] = '"' + str(version) + '"'
    return await browser.client.request(
        method, "/api/v1/status/" + path, headers=headers, json=body
    )


async def test_real_persistence_recovery_rbac_and_stale(browser: Browser) -> None:
    value = collector(browser)
    try:
        admin = await actor(browser)
        analyst = await actor(browser, ("security_analyst",))
        viewer = await actor(browser, ("viewer",))
        from scripts.database import manage as db

        with browser.lab.owner() as s:
            s.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
        with db.connect(browser.lab.config, "workflow_control") as s:
            s.execute("SELECT automation.n8n_touch('status-fixture','cve-control-queue')")
        await store(value)
        result = await call(browser, admin, "GET", "overview")
        assert result.status_code == 200, result.text
        assert result.json()["state"] == "healthy"
        assert "http://" not in result.text and "password" not in result.text
        assert (await call(browser, analyst, "GET", "overview")).status_code == 403
        assert (await call(browser, analyst, "GET", "services/api")).status_code == 403
        assert (await call(browser, viewer, "GET", "overview")).status_code == 403
        assert (
            await browser.client.get("/api/v1/status/overview", headers={"cookie": ""})
        ).status_code == 401
        await store(value, "unavailable")
        await store(value, "unavailable")
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT count(*) n FROM status.incidents WHERE entity_id='api' AND state='open'"
                ).fetchone()["n"]
                == 1
            )
        await store(value, "unknown")
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT count(*) n FROM status.incidents WHERE entity_id='api' AND state='open'"
                ).fetchone()["n"]
                == 1
            )
        await store(value)
        assert (await call(browser, admin, "GET", "services/api")).json()["state"] == "degraded"
        await store(value)
        assert (await call(browser, admin, "GET", "services/api")).json()["state"] == "healthy"
        with browser.lab.owner() as c:
            c.execute(
                "UPDATE status.current_states SET observed_at=clock"
                "_timestamp()-interval '10 minutes'"
            )
        stale = await call(browser, admin, "GET", "overview")
        assert stale.status_code == 200 and stale.json()["state"] == "unknown", stale.text
        history = await call(browser, admin, "GET", "services/api/history?limit=1&offset=0")
        assert history.status_code == 200, history.text
        assert len(history.json()["items"]) == 1 and history.json()["total"] > 1
        assert (
            await call(browser, admin, "GET", "services/api/history?limit=101")
        ).status_code == 422
    finally:
        await value.database.close()


async def test_maintenance_requires_csrf_stepup_and_version(browser: Browser) -> None:
    from tests.authorization.integration.conftest import fresh

    value = collector(browser)
    try:
        await store(value, "unavailable")
        admin = await actor(browser)
        analyst = await actor(browser, ("security_analyst",))
        now = datetime.now(UTC)
        body = {
            "service_ids": ["api"],
            "starts_at": (now - timedelta(minutes=1)).isoformat(),
            "ends_at": (now + timedelta(hours=1)).isoformat(),
            "description": "Geplante <script> Wartung",
            "reason": "Explicit scheduled maintenance",
        }
        forbidden = await call(browser, analyst, "POST", "admin/maintenance", body)
        assert forbidden.status_code == 403
        fresh(browser, admin)
        no_csrf = await browser.client.post(
            "/api/v1/status/admin/maintenance",
            json=body,
            headers={"cookie": "__Host-cve-session=" + admin.cookie, "x-csrf-token": ""},
        )
        assert no_csrf.status_code == 403
        fresh(browser, admin)
        created = await call(browser, admin, "POST", "admin/maintenance", body)
        assert created.status_code == 200, created.text
        identity = created.json()["id"]
        detail = await call(browser, admin, "GET", "services/api")
        assert (
            detail.json()["raw_state"] == "unavailable"
            and detail.json()["display_state"] == "maintenance"
        ), detail.text
        fresh(browser, admin)
        missing = await call(browser, admin, "PUT", "admin/maintenance/" + identity, body)
        assert missing.status_code == 428, missing.text
        fresh(browser, admin)
        updated = await call(browser, admin, "PUT", "admin/maintenance/" + identity, body, 1)
        assert updated.status_code == 200 and updated.json()["version"] == 2, updated.text
        fresh(browser, admin)
        conflict = await call(browser, admin, "PUT", "admin/maintenance/" + identity, body, 1)
        assert conflict.status_code == 412, conflict.text
        fresh(browser, admin)
        cancelled = await call(
            browser,
            admin,
            "DELETE",
            "admin/maintenance/" + identity,
            {"reason": "Cancelled explicitly"},
            2,
        )
        assert cancelled.status_code == 200, cancelled.text
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT count(*) n FROM status.audit WHERE object_id=%s", (identity,)
                ).fetchone()["n"]
                == 3
            )
            assert (
                c.execute(
                    "SELECT raw_state FROM status.current_states WHERE entity_id='api'"
                ).fetchone()["raw_state"]
                == "unavailable"
            )
        audit = await browser.client.get(
            ("/api/v1/dashboard/administration/audit?action=status.maintenance"),
            headers={("cookie"): ("__Host-cve-session=") + admin.cookie},
        )
        assert audit.status_code == 200 and audit.json()["total"] >= 3, audit.text
        fresh(browser, admin)
        assert (
            await call(
                browser,
                admin,
                "POST",
                "admin/maintenance",
                {**body, "service_ids": ["http://169.254.169.254/"]},
            )
        ).status_code == 422
        assert (await call(browser, admin, "GET", "services/not-a-service")).status_code == 404
    finally:
        await value.database.close()


async def test_concurrent_runs_immutability_and_minimum_privileges(browser: Browser) -> None:
    import asyncio

    import psycopg

    value = collector(browser)
    second = collector(browser)
    try:
        await asyncio.gather(store(value, "unavailable"), store(second, "unavailable"))
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT count(*) n FROM status.incidents WHERE entity_id='api' AND state='open'"
                ).fetchone()["n"]
                == 1
            )
            assert not c.execute(
                "SELECT has_table_privilege('status_probe','security.users','SELECT') v"
            ).fetchone()["v"]
            assert not c.execute(
                "SELECT has_table_privilege('status_probe','inventory.servers','UPDATE') v"
            ).fetchone()["v"]
            assert not c.execute(
                "SELECT has_table_privilege('status_probe','findings.findings','UPDATE') v"
            ).fetchone()["v"]
            assert not c.execute(
                "SELECT has_database_privilege('status_probe','n8n','CONNECT') v"
            ).fetchone()["v"]
            assert not c.execute(
                "SELECT rolsuper FROM pg_roles WHERE rolname='status_probe'"
            ).fetchone()["rolsuper"]
        from scripts.database import manage as db

        with db.connect(browser.lab.config, "status_probe") as c:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute("UPDATE status.check_observations SET result='healthy'")
            c.rollback()
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute("DELETE FROM status.state_history")
            c.rollback()
            sampled_row = c.execute("SELECT status.sample() AS value").fetchone()
            assert sampled_row is not None
            sampled = sampled_row["value"]
            assert "payload" not in str(sampled) and "password" not in str(sampled)
            assert "jobs" in sampled and "intake" in sampled and "enrichment" in sampled
    finally:
        await value.database.close()
        await second.database.close()


async def test_alert_handoff_is_deduplicated_and_rechecks_recipient(browser: Browser) -> None:
    import json

    from cve_common.database.engine import Database
    from cve_notification.contracts import EVENTS, STATUS_EVENTS, Preferences, Request, Rule
    from cve_notification.service import Service
    from cve_notification.status_alerts import dispatch_content

    value = collector(browser)
    notifier = Database(browser.lab.database("notification"))
    notifier.open()
    try:
        admin = await actor(browser)
        viewer = await actor(browser, ("viewer",))
        prefs = Preferences(event_types=sorted(EVENTS | STATUS_EVENTS))
        rule = Rule(
            event_types=sorted(STATUS_EVENTS),
            recipients="administrators",
            mode="immediate",
            minimum_priority="critical",
            allowed_domains=["example.test"],
        )
        with browser.lab.owner() as c:
            c.execute(
                (
                    "INSERT INTO automation.notification_preferences(us"
                    "er_id,version,config) VALUES(%s,1,%s::jsonb)"
                ),
                (admin.id, prefs.model_dump_json()),
            )
            row = c.execute(
                (
                    "INSERT INTO automation.notification_rules(rule_key"
                    ",version,config,reason) VALUES(%s,1,%s::jsonb,%s) "
                    "RETURNING id"
                ),
                (uuid4(), rule.model_dump_json(), "Isolated status alert approval"),
            ).fetchone()
            rule_id = row["id"]
        await store(value)
        await store(value)
        await store(value, "unavailable")
        await store(value, "unavailable")
        with browser.lab.owner() as c:
            event = c.execute(
                "SELECT * FROM automation.event_outbox WHERE source"
                "='cve-status' AND event_type='monitoring.status_un"
                "available' ORDER BY occurred_at DESC,id DESC LIMIT"
                " 1"
            ).fetchone()
            event_id = event["id"]
            assert (
                c.execute(
                    "SELECT count(*) n FROM status.alert_receipts WHERE incident_id=%s",
                    (event["aggregate_id"],),
                ).fetchone()["n"]
                == 1
            )
        service = Service(notifier)
        async with transaction(notifier) as s:
            assert await service.consume(s, Request(event_id=event_id), uuid4()) >= 1
        async with transaction(notifier) as s:
            assert await service.consume(s, Request(event_id=event_id), uuid4()) == 0
        with browser.lab.owner() as c:
            intents = c.execute(
                (
                    "SELECT * FROM automation.notification_intents WHER"
                    "E event_id=%s AND rule_id=%s AND recipient_user_id"
                    "=%s"
                ),
                (event_id, rule_id, admin.id),
            ).fetchall()
            assert len(intents) == 1 and intents[0]["status"] == "ready"
            assert intents[0]["finding_id"] is None and intents[0]["status_incident_id"]
            assert (
                c.execute(
                    (
                        "SELECT count(*) n FROM automation.notification_int"
                        "ents WHERE event_id=%s AND recipient_user_id=%s"
                    ),
                    (event_id, viewer.id),
                ).fetchone()["n"]
                == 0
            )
            assert not c.execute(
                "SELECT 1 FROM automation.notification_delivery_attempts WHERE notification_id=%s",
                (intents[0]["id"],),
            ).fetchone()
        async with transaction(notifier) as s:
            assert await dispatch_content(s, dict(intents[0]), admin.id, rule, prefs)
        from typing import cast

        from cve_notification.dispatch import Dispatch
        from cve_notification.repository import one
        from cve_notification.smtp import Adapter

        from tests.notifications.test_native import FakeRelay

        relay = FakeRelay()
        dispatch = Dispatch(
            notifier,
            cast(Adapter, relay),
            sender="security@example.test",
            base="https://dashboard.example.test",
            relay_instance="isolated-status-relay",
        )
        async with transaction(notifier) as s:
            workflow = await one(
                s,
                (
                    "INSERT INTO automation.notification_workflow_runs("
                    "notification_id,workflow,workflow_version,request_"
                    "id,state,expires_at) VALUES(:id,'dispatch',1,:requ"
                    "est,'requested',clock_timestamp()+interval '5 minu"
                    "tes') RETURNING id,request_id"
                ),
                id=intents[0]["id"],
                request=uuid4(),
            )
            assert workflow
        assert (await dispatch.claim(workflow["id"], workflow["request_id"]))["claimed"]
        await dispatch.execute(workflow["id"], workflow["request_id"])
        await dispatch.execute(workflow["id"], workflow["request_id"])
        assert relay.calls == 1
        assert "Systemstatus" in relay.messages[0].get_body(preferencelist=("plain",)).get_content()
        assert "/status" in relay.messages[0].get_body(preferencelist=("plain",)).get_content()
        with browser.lab.owner() as c:
            c.execute("DELETE FROM security.user_roles WHERE user_id=%s", (admin.id,))
        async with transaction(notifier) as s:
            assert await dispatch_content(s, dict(intents[0]), admin.id, rule, prefs) is None
        assert "password" not in json.dumps(dict(event), default=str)
    finally:
        await notifier.close()
        await value.database.close()


async def test_gather_contract_and_sampling_has_no_duplicate_checks(
    browser: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cve_api.status import probes

    value = collector(browser)

    async def probe(settings: Settings, service: str, dimension: str) -> Observation:
        return probes.observation(service, dimension, "healthy", "CHECK_CONFIRMED")

    monkeypatch.setattr(probes, "http", probe)
    try:
        observations = await value.gather()
        keys = [(o.service_id, o.check_id) for o in observations]
        assert len(keys) == len(set(keys))
        assert ("notification", "backlog") in keys and ("matcher", "freshness") in keys
        async with transaction(value.database) as s:
            await value.persist(s, observations, datetime.now(UTC) - timedelta(seconds=1), uuid4())
    finally:
        await value.database.close()


async def test_retention_preserves_history_and_out_of_order_does_not_rewind(
    browser: Browser,
) -> None:
    from scripts.database import manage as db

    value = collector(browser)
    try:
        await store(value)
        await store(value)
        with browser.lab.owner() as c:
            before = dict(
                c.execute(
                    "SELECT state,observed_at,version FROM status.curre"
                    "nt_states WHERE entity_id='api'"
                ).fetchone()
            )
        older = samples("unavailable")
        older = [
            o.model_copy(update={"checked_at": before["observed_at"] - timedelta(seconds=1)})
            for o in older
        ]
        async with transaction(value.database) as s:
            await value.persist(s, older, datetime.now(UTC) - timedelta(seconds=2), uuid4())
        with browser.lab.owner() as c:
            after = dict(
                c.execute(
                    "SELECT state,observed_at,version FROM status.curre"
                    "nt_states WHERE entity_id='api'"
                ).fetchone()
            )
            assert before == after
            history = c.execute("SELECT count(*) n FROM status.state_history").fetchone()["n"]
            run = uuid4()
            c.execute(
                (
                    "INSERT INTO status.monitoring_runs(id,started_at,f"
                    "inished_at,correlation_id,observation_count) VALUE"
                    "S(%s,clock_timestamp()-interval '20 days',clock_ti"
                    "mestamp()-interval '20 days',%s,1)"
                ),
                (run, uuid4()),
            )
            c.execute(
                (
                    "INSERT INTO status.check_observations(run_id,servi"
                    "ce_id,check_id,checked_at,result,duration_ms,reaso"
                    "n_code,metrics) VALUES(%s,'api','readiness',clock_"
                    "timestamp()-interval '20 days','healthy',1,'CHECK_"
                    "CONFIRMED','{}')"
                ),
                (run,),
            )
        with db.connect(browser.lab.config, "status_probe") as c:
            removed = c.execute("SELECT status.prune(14) n").fetchone()
            assert removed and removed["n"] >= 1
        with browser.lab.owner() as c:
            assert (
                c.execute("SELECT count(*) n FROM status.state_history").fetchone()["n"] == history
            )
            assert (
                c.execute(
                    "SELECT count(*) n FROM status.check_observations WHERE run_id=%s", (run,)
                ).fetchone()["n"]
                == 0
            )
    finally:
        await value.database.close()


async def test_hundred_checks_and_bounded_history_performance(browser: Browser) -> None:
    import time

    value = collector(browser)
    try:
        now = datetime.now(UTC)
        items = [
            Observation(
                service_id="api",
                check_id=f"probe_{n}",
                checked_at=now,
                result="healthy",
                duration_ms=n,
                reason_code="CHECK_CONFIRMED",
            )
            for n in range(100)
        ]
        start = time.monotonic()
        async with transaction(value.database) as s:
            await value.persist(s, items, now, uuid4())
        elapsed = (time.monotonic() - start) * 1000
        assert elapsed < 8000, elapsed
        admin = await actor(browser)
        start = time.monotonic()
        response = await call(browser, admin, "GET", "services/api/history?limit=25&hours=744")
        latency = (time.monotonic() - start) * 1000
        assert response.status_code == 200 and len(response.json()["items"]) <= 25, response.text
        assert len(response.json()["samples"]) <= 2000 and latency < 2000
        import json

        (
            browser.lab.config.root / ".runtime/test-reports/phase-22-database-performance.json"
        ).write_text(
            json.dumps(
                {
                    "observations": 100,
                    "persist_ms": elapsed,
                    "history_ms": latency,
                    "history_items": len(response.json()["items"]),
                    "sample_count": len(response.json()["samples"]),
                },
                indent=2,
            )
        )
    finally:
        await value.database.close()


async def test_admin_role_is_required_even_when_status_permissions_are_granted(
    browser: Browser,
) -> None:
    person = await actor(browser, ("security_analyst",))
    with browser.lab.owner() as db:
        added = db.execute(
            "INSERT INTO security.role_permissions(role_id,permission_code) "
            "SELECT r.id,p.code FROM security.roles r CROSS JOIN security.permissions p "
            "WHERE r.code='security_analyst' AND p.code LIKE 'deployment:%' "
            "ON CONFLICT DO NOTHING RETURNING permission_code"
        ).fetchall()
    try:
        for path in [
            "overview",
            "services",
            "pipelines",
            "services/api",
            "pipelines/importer",
            "services/api/history",
            "incidents",
            "maintenance",
            "admin/restarts",
        ]:
            result = await call(browser, person, "GET", path)
            assert result.status_code == 403, (path, result.text)
        result = await browser.client.post(
            "/api/v1/status/services/importer/restart",
            json={"reason": "Must not restart as non-admin"},
            headers={
                "cookie": "__Host-cve-session=" + person.cookie,
                "x-csrf-token": person.csrf,
                "idempotency-key": str(uuid4()),
            },
        )
        assert result.status_code == 403, result.text
    finally:
        with browser.lab.owner() as db:
            db.execute(
                "DELETE FROM security.role_permissions p USING security.roles r "
                "WHERE p.role_id=r.id AND r.code='security_analyst' "
                "AND p.permission_code=ANY(%s)",
                ([row["permission_code"] for row in added],),
            )
