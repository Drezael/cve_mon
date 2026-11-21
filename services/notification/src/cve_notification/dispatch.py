"Commit submit intent before I/O, revalidate recipients, fence completion and never blindly resend."

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from sqlalchemy import text

from cve_notification.contracts import Preferences, Rule, Template
from cve_notification.mail_settings import destinations, route
from cve_notification.rendering import finding_line, message
from cve_notification.repository import change, one, record, rows, rule_active
from cve_notification.rules import address, applies, next_allowed, preference_reason, window
from cve_notification.smtp import Adapter, Outcome


class Dispatch:
    def __init__(
        self,
        database: Database,
        adapter: Adapter,
        *,
        sender: str,
        base: str,
        relay_instance: str,
        configuration_dir: Path | None = None,
    ) -> None:
        self.configuration_dir = configuration_dir
        self.database, self.adapter, self.sender, self.base, self.relay_instance = (
            database,
            adapter,
            sender,
            base,
            relay_instance,
        )

    async def claim(self, run_id: UUID, request_id: UUID) -> dict[str, Any]:
        async with transaction(self.database) as s:
            run = await one(
                s,
                (
                    "SELECT * FROM automation.notification_workflow_runs WHERE id=:id "
                    "AND request_id=:request AND expires_at>clock_timestamp() FOR UPDA"
                    "TE"
                ),
                id=run_id,
                request=request_id,
            )
            if not run or run["state"] != "requested" or run["callback_seen"]:
                return {"claimed": False}
            await s.execute(
                text(
                    "UPDATE automation.notification_workflow_runs SET state='executing"
                    "',callback_seen=true WHERE id=:id"
                ),
                {"id": run_id},
            )
            if run["workflow"] != "dispatch":
                return {"claimed": True}
            n = await one(
                s,
                (
                    "SELECT * FROM automation.notification_intents WHERE id=:id AND st"
                    "atus='ready' AND scheduled_at<=clock_timestamp() FOR UPDATE"
                ),
                id=run["notification_id"],
            )
            if not n:
                await s.execute(
                    text(
                        "UPDATE automation.notification_workflow_runs SET state='completed"
                        "',completed_at=clock_timestamp() WHERE id=:id"
                    ),
                    {"id": run_id},
                )
                return {"claimed": False}
            await s.execute(
                text(
                    "UPDATE automation.notification_intents SET status='leased',reason"
                    "='workflow_claim',version=version+1,lease_owner=:run,lease_until="
                    "clock_timestamp()+interval '30 seconds',fencing_token=fencing_tok"
                    "en+1 WHERE id=:id"
                ),
                {"id": n["id"], "run": run_id},
            )
            await record(s, n["id"], n["status"], "workflow_claim")
            return {"claimed": True}

    async def execute(self, run_id: UUID, request_id: UUID) -> dict[str, Any]:
        prepared = None
        async with transaction(self.database) as s:
            run = await one(
                s,
                (
                    "SELECT * FROM automation.notification_workflow_runs WHERE id=:id "
                    "AND request_id=:request AND state='executing' AND expires_at>cloc"
                    "k_timestamp() FOR UPDATE"
                ),
                id=run_id,
                request=request_id,
            )
            if not run:
                return {"executed": False}
            if run["workflow"] != "dispatch":
                from cve_notification.service import Service

                await Service(self.database).maintenance(s, run["request_id"])
                await s.execute(
                    text(
                        "UPDATE automation.notification_workflow_runs SET state='completed"
                        "',completed_at=clock_timestamp() WHERE id=:id"
                    ),
                    {"id": run_id},
                )
                return {"executed": True}
            n = await one(
                s,
                (
                    "SELECT * FROM automation.notification_intents WHERE id=:id AND st"
                    "atus='leased' AND lease_owner=:run AND lease_until>clock_timestam"
                    "p() FOR UPDATE"
                ),
                id=run["notification_id"],
                run=run_id,
            )
            if not n:
                return {"executed": False}
            user = await one(
                s,
                (
                    "SELECT "
                    "u.id,u.email,u.status,p.config,automation.personal_mail(u.id) "
                    "AS mail_config FROM security.users u LEFT "
                    "JOIN automation.notification_preferences p ON p.user_id=u.id WHER"
                    "E u.id=:id"
                ),
                id=n["recipient_user_id"],
            )
            r = await one(
                s, "SELECT * FROM automation.notification_rules WHERE id=:id", id=n["rule_id"]
            )
            assert user and r
            rule = Rule.model_validate(r["config"])
            prefs = Preferences.model_validate(user["config"] or {})
            addresses = destinations(user["mail_config"], user["email"] or "")
            transport = (
                route(self.configuration_dir, str(user["id"]), user["mail_config"])
                if self.configuration_dir
                else None
            )
            reason = (
                "smtp_transport_unavailable"
                if self.configuration_dir
                and (
                    (self.configuration_dir / "smtp-delivery.json").exists()
                    or user["mail_config"] is not None
                )
                and not transport
                else None
            )
            if not await rule_active(s, r):
                reason = "rule_superseded_or_disabled"
            elif (
                user["status"] != "active"
                or not addresses
                or not all(address(item, rule.allowed_domains) for item in addresses)
            ):
                reason = "recipient_disabled_or_invalid"
            from cve_notification.reports import content as report_content

            server_report = await report_content(s, n["id"], user["id"], prefs)
            if server_report is not None and server_report[1] == "scan_not_complete":
                await change(
                    s, n, "deferred", "scan_running", due=datetime.now(UTC) + timedelta(seconds=30)
                )
                await s.execute(
                    text(
                        "UPDATE automation.notification_workflow_runs SET state='completed',"
                        "completed_at=clock_timestamp() WHERE id=:id"
                    ),
                    {"id": run_id},
                )
                return {"executed": True, "deferred": True}
            children = (
                await rows(
                    s,
                    (
                        "SELECT * FROM automation.notification_intents WHERE digest_id=:id"
                        " ORDER BY id FOR UPDATE"
                    ),
                    id=n["id"],
                )
                if n["kind"] == "digest"
                else [n]
            )
            current_findings = await rows(
                s,
                "SELECT f.*,s.created_by AS server_owner_id,"
                "automation.notification_recipient(:user,f.id) AS eligible "
                "FROM findings.current_findings f JOIN inventory.servers s "
                "ON s.id=f.server_id WHERE f.id=ANY(:ids)",
                user=user["id"],
                ids=[child["finding_id"] for child in children],
            )
            by_id = {f["id"]: f for f in current_findings}
            content = []
            critical = False
            for child in [] if server_report is not None else children:
                if child["kind"] in {"status_unavailable", "status_recovered"}:
                    from cve_notification.status_alerts import dispatch_content

                    status_line = await dispatch_content(s, child, user["id"], rule, prefs)
                    if status_line is None:
                        reason = reason or "status_recipient_or_event_no_longer_authorized"
                    else:
                        critical = True
                        content.append(("critical", status_line))
                    continue
                f = by_id.get(child["finding_id"])
                no_longer_actionable = bool(
                    f
                    and f["status"] in {"resolved", "closed"}
                    and child["kind"]
                    in {
                        "created",
                        "confirmed_affected",
                        "potentially_affected",
                        "reopened",
                        "overdue",
                        "deadline_approaching",
                    }
                )
                failure = (
                    "finding_no_longer_actionable"
                    if no_longer_actionable
                    else "recipient_not_authorized"
                    if not f
                    or not f["eligible"]
                    or rule.recipients == "server_owner"
                    and f["server_owner_id"] != user["id"]
                    else "finding_outside_rule"
                    if not applies(rule, child["kind"], f)
                    else preference_reason(rule, prefs, child["kind"], f)
                )
                if failure:
                    if child["id"] != n["id"]:
                        if child["status"] == "deferred":
                            await change(s, child, "suppressed", failure)
                    else:
                        reason = reason or failure
                    continue
                assert f
                critical = critical or f["current_priority"] == "critical"
                content.append(
                    (f["current_priority"], finding_line(f, child["kind"], prefs.timezone))
                )
            if server_report is not None:
                content, report_subject, send_now = server_report
                if not content:
                    reason = reason or report_subject
            if not content:
                reason = reason or "empty_or_unauthorized_digest"
            now = datetime.now(UTC)
            if now > n["created_at"] + timedelta(hours=rule.max_deferral_hours):
                reason = reason or "maximum_deferral_reached"
            if reason:
                await change(s, n, "suppressed", reason)
            else:
                due = (
                    now
                    if (server_report is not None and send_now)
                    or (rule.critical_bypass and critical)
                    else max(next_allowed(now, rule.quiet), next_allowed(now, prefs.quiet))
                )
                await s.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:key,19))"),
                    {"key": "notification-rate:" + str(user["id"])},
                )
                start, end = window(now, 1)
                counts = await one(
                    s,
                    (
                        "SELECT coalesce(sum(used),0) AS total,coalesce(sum(used) FILTER(W"
                        "HERE rule_id=:rule),0) AS current FROM automation.notification_ra"
                        "te_limits WHERE recipient_user_id=:user AND window_start=:start"
                    ),
                    user=user["id"],
                    rule=r["id"],
                    start=start,
                )
                assert counts
                if counts["total"] >= 100 or counts["current"] >= rule.rate_per_hour:
                    due = max(due, end)
                if due > now:
                    await change(s, n, "deferred", "quiet_time_or_rate_limit", due=due)
                else:
                    t = await one(
                        s,
                        "SELECT content FROM automation.notification_templates WHERE id=:id",
                        id=n["template_id"],
                    )
                    assert t
                    template = Template.model_validate(t["content"])
                    content.sort(
                        key=lambda item: {
                            "critical": 0,
                            "high": 1,
                            "medium": 2,
                            "low": 3,
                            "unrated": 4,
                        }[item[0]]
                    )
                    mail = message(
                        template,
                        notification_id=str(n["id"]),
                        sender=transport["sender"] if transport else self.sender,
                        recipient=addresses[0],
                        base=self.base,
                        items=[item[1] for item in content],
                        section="status"
                        if n["kind"] in {"status_unavailable", "status_recovered"}
                        else "findings",
                    )
                    if server_report is not None:
                        from cve_notification.reports import render_report

                        if not render_report(
                            mail, report_subject, [item[1] for item in content], self.base
                        ):
                            await change(s, n, "permanent_failure", "report_size_limit")
                            await s.execute(
                                text(
                                    "UPDATE automation.notification_workflow_runs "
                                    "SET state='completed',"
                                    "completed_at=clock_timestamp() WHERE id=:id"
                                ),
                                {"id": run_id},
                            )
                            return {"executed": True, "status": "permanent_failure"}
                    if len(addresses) > 1:
                        mail.replace_header("To", ", ".join(addresses))
                    if n["attempts"] >= 5:
                        await change(s, n, "permanent_failure", "maximum_attempts_reached")
                    else:
                        attempt = uuid4()
                        await s.execute(
                            text(
                                "UPDATE automation.notification_intents SET status='submitting',re"
                                "ason='smtp_submit_started',version=version+1,attempts=attempts+1,"
                                "lease_until=clock_timestamp()+interval '30 seconds' WHERE id=:id"
                            ),
                            {"id": n["id"]},
                        )
                        await record(s, n["id"], n["status"], "smtp_submit_started")
                        await s.execute(
                            text(
                                "INSERT INTO automation.notification_delivery_attempts(id,notifica"
                                "tion_id,attempt,fencing_token,worker_id,message_id) VALUES(:id,:n"
                                "otification,:attempt,:fence,:worker,:message)"
                            ),
                            {
                                "id": attempt,
                                "notification": n["id"],
                                "attempt": n["attempts"] + 1,
                                "fence": n["fencing_token"],
                                "worker": run_id,
                                "message": n["message_id"],
                            },
                        )
                        await s.execute(
                            text(
                                "INSERT INTO automation.notification_rate_limits(recipient_user_id"
                                ",rule_id,window_start,used) VALUES(:user,:rule,:start,1) ON CONFL"
                                "ICT(recipient_user_id,rule_id,window_start) DO UPDATE SET used=au"
                                "tomation.notification_rate_limits.used+1"
                            ),
                            {"user": user["id"], "rule": r["id"], "start": start},
                        )
                        prepared = (n, attempt, mail, transport, addresses)
            if prepared is None:
                await s.execute(
                    text(
                        "UPDATE automation.notification_workflow_runs SET state='completed"
                        "',completed_at=clock_timestamp() WHERE id=:id"
                    ),
                    {"id": run_id},
                )
        if prepared is None:
            return {"executed": True}
        n, attempt, mail, transport, addresses = prepared
        # No open PostgreSQL transaction while communicating with SMTP.
        outcome = (
            await asyncio.to_thread(
                self.adapter.submit,
                mail,
                envelope_sender=transport["envelope_sender"],
                recipients=addresses,
            )
            if transport
            else await asyncio.to_thread(self.adapter.submit, mail)
        )
        await self.finish(n, attempt, run_id, outcome)
        return {"executed": True, "status": outcome.status}

    async def finish(
        self, n: dict[str, Any], attempt: UUID, run_id: UUID, outcome: Outcome
    ) -> None:
        async with transaction(self.database) as s:
            await s.execute(
                text(
                    "INSERT INTO automation.notification_delivery_results(attempt_id,s"
                    "tatus,reason,smtp_code,queue_id,relay_instance) VALUES(:attempt,:"
                    "status,:reason,:smtp,:queue,:relay) ON CONFLICT DO NOTHING"
                ),
                {
                    "attempt": attempt,
                    "status": outcome.status,
                    "reason": outcome.code,
                    "smtp": outcome.smtp_code,
                    "queue": outcome.queue_id,
                    "relay": self.relay_instance,
                },
            )
            current = await one(
                s,
                (
                    "SELECT * FROM automation.notification_intents WHERE id=:id AND st"
                    "atus='submitting' AND lease_owner=:run AND fencing_token=:fence F"
                    "OR UPDATE"
                ),
                id=n["id"],
                run=run_id,
                fence=n["fencing_token"],
            )
            if current:
                due = (
                    datetime.now(UTC)
                    + timedelta(seconds=min(3600, 30 * 2 ** n["attempts"]) + (n["id"].int % 17))
                    if outcome.status == "retryable_failure"
                    else None
                )
                await change(s, current, outcome.status, outcome.code, due=due)
            await s.execute(
                text(
                    "UPDATE automation.notification_workflow_runs SET state='completed"
                    "',completed_at=clock_timestamp() WHERE id=:id"
                ),
                {"id": run_id},
            )
