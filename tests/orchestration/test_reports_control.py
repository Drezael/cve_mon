"""n8n owns report startup; weekly reports include every managed server and retain zero findings."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_notification.contracts import Preferences
from cve_notification.reports import content, maintain
from psycopg.types.json import Jsonb

from scripts.database import manage as db
from tests.cve_importer.conftest import Lab
from tests.orchestration.test_epss_control import epss_lab

__all__ = ["epss_lab"]
pytestmark = pytest.mark.orchestration


async def test_n8n_report_request_and_complete_clean_servers(epss_lab: Lab) -> None:
    with epss_lab.owner() as s:
        actor = s.execute(
            "INSERT INTO security.users(username,email,display_name,status) VALUES('re"
            "porter','reporter@example.test','Reporter','active') RETURNING id"
        ).fetchone()
        assert actor
        s.execute(
            "INSERT INTO security.user_roles(user_id,role_id) SELECT %s,id FROM securi"
            "ty.roles WHERE code='admin'",
            (actor["id"],),
        )
        for name in ["clean-one", "clean-two"]:
            s.execute(
                "INSERT INTO inventory.servers(display_name,inventory_hostname,invento"
                "ry_name,created_by,updated_by) VALUES(%s,%s,'weekly-test',%s,%s)",
                (name, name, actor["id"], actor["id"]),
            )
        s.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")
    key = uuid4()
    with db.connect(epss_lab.config, "api_security") as s:
        first = s.execute(
            "SELECT automation.request_mail_report(%s,%s) value", (actor["id"], key)
        ).fetchone()
        again = s.execute(
            "SELECT automation.request_mail_report(%s,%s) value", (actor["id"], key)
        ).fetchone()
        assert first == again
    with epss_lab.owner() as s:
        assert s.execute(
            "SELECT state FROM automation.mail_reports WHERE id=%s", (key,)
        ).fetchone() == {"state": "requested"}
    with db.connect(epss_lab.config, "workflow_control") as s:
        for _ in range(64):
            row = s.execute(
                "SELECT automation.n8n_claim('report-test','cve-control-queue') v"
            ).fetchone()
            assert row and row["v"]["kind"] != "empty"
            q = row["v"]
            s.execute(
                "SELECT automation.n8n_decide(%s,%s,%s,'report-test','cve-control-queue')",
                (q["id"], q["lease_token"], q["kind"]),
            )
            if q["message_type"] == "reports.scan":
                break
    database = Database(epss_lab.settings("notification"))
    database.open()
    try:
        async with transaction(database) as s:
            assert await maintain(s, uuid4()) == 1
        async with transaction(database) as s:
            assert await maintain(s, uuid4()) == 0
        with epss_lab.owner() as s:
            report = s.execute(
                "SELECT notification_id,state FROM automation.mail_reports WHERE id=%s", (key,)
            ).fetchone()
            assert report and report["state"] == "ready"
            assert s.execute(
                "SELECT count(*) n FROM automation.mail_report_servers WHERE report_id=%s", (key,)
            ).fetchone() == {"n": 2}
        async with transaction(database) as s:
            body = await content(s, report["notification_id"], actor["id"], Preferences())
            assert body
            text = "\n".join(line for _, line in body[0])
            assert "clean-one" in text and "clean-two" in text
            assert "Wochenbericht für 2 Server" in body[1]
    finally:
        await database.close()


def test_weekly_timezones_and_due_tick(epss_lab: Lab) -> None:
    cfg = {"enabled": True, "weekday": 0, "time": "09:00", "timezone": "Europe/Berlin"}
    with epss_lab.owner() as s:
        # Summer and winter preserve 09:00 local time; a missed interval schedules
        # one report rather than mailing every missed week after downtime.
        for after, expected in [
            ("2026-03-28T12:00:00Z", "2026-03-30T07:00:00+00:00"),
            ("2026-10-24T12:00:00Z", "2026-10-26T08:00:00+00:00"),
        ]:
            row = s.execute(
                "SELECT automation.report_next_run(%s,%s::timestamptz) next", (Jsonb(cfg), after)
            ).fetchone()
            assert row and row["next"].isoformat() == expected
        actor = s.execute(
            "INSERT INTO security.users(username,email,display_name,status) VALUES('we"
            "ekly','weekly@example.test','Weekly','active') RETURNING id"
        ).fetchone()
        assert actor
        s.execute(
            "INSERT INTO automation.mail_report_schedules(user_id,configuration,next_r"
            "un_at) VALUES(%s,%s,%s)",
            (actor["id"], Jsonb(cfg), datetime(2026, 1, 1, tzinfo=UTC)),
        )
    with db.connect(epss_lab.config, "notification") as s:
        assert s.execute("SELECT automation.report_weekly_tick() n").fetchone() == {"n": 1}
        assert s.execute("SELECT automation.report_weekly_tick() n").fetchone() == {"n": 0}
    with epss_lab.owner() as s:
        assert s.execute(
            "SELECT count(*) n FROM automation.mail_reports WHERE user_id=%s AND origin='weekly'",
            (actor["id"],),
        ).fetchone() == {"n": 1}


async def test_failed_scan_does_not_send_a_partial_report(epss_lab: Lab) -> None:
    key = uuid4()
    with epss_lab.owner() as s:
        actor = s.execute(
            "INSERT INTO security.users(username,email,display_name,status) VALUES('fa"
            "iledscan','scan@example.test','Scan','active') RETURNING id"
        ).fetchone()
        assert actor
        s.execute(
            "INSERT INTO automation.mail_reports(id,user_id,origin,correlation_id,stat"
            "e) VALUES(%s,%s,'manual',%s,'scanning')",
            (key, actor["id"], key),
        )
    with db.connect(epss_lab.config, "matcher") as s:
        job = s.execute(
            "SELECT id FROM automation.enqueue_job('matching.evaluate_snapshot',1,%s,%"
            "s,%s,0,NULL,NULL,3,'test',false)",
            (Jsonb({"snapshot_id": str(uuid4())}), str(key), key),
        ).fetchone()
        assert job
    database = Database(epss_lab.settings("notification"))
    database.open()
    try:
        async with transaction(database) as s:
            assert await maintain(s, uuid4()) == 0
        with epss_lab.owner() as s:
            assert s.execute(
                "SELECT state FROM automation.mail_reports WHERE id=%s", (key,)
            ).fetchone() == {"state": "scanning"}
            s.execute("UPDATE automation.jobs SET status='cancelled' WHERE id=%s", (job["id"],))
        async with transaction(database) as s:
            assert await maintain(s, uuid4()) == 0
        with epss_lab.owner() as s:
            row = s.execute(
                "SELECT state,error_code,notification_id FROM automation.mail_reports WHERE id=%s",
                (key,),
            ).fetchone()
            assert row == {"state": "failed", "error_code": "scan_failed", "notification_id": None}
    finally:
        await database.close()
