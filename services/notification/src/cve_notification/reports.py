"""One durable report per complete server scan, or one weekly mail for all managed servers."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_notification.contracts import Preferences
from cve_notification.mail_settings import destinations
from cve_notification.repository import insert, one, rows
from cve_notification.rules import address

RULE_KEY = "00000000-0000-0000-0000-000000000067"


async def track(s: AsyncSession, event: dict[str, Any], finding: dict[str, Any]) -> None:
    if event["event_type"] != "finding.created" or finding["status"] not in {"open", "in_progress"}:
        return
    if str(event["payload"].get("episode_id")) != str(finding["current_episode_id"]):
        return
    owner = finding["server_owner_id"]
    if owner is None:
        return
    preferences = await one(
        s, "SELECT config FROM automation.notification_preferences WHERE user_id=:user", user=owner
    )
    prefs = Preferences.model_validate(preferences["config"] if preferences else {})
    from cve_notification.rules import ORDER

    if (
        not prefs.enabled
        or "created" not in prefs.event_types
        or ORDER[finding["current_priority"]] < ORDER[prefs.minimum_priority]
    ):
        return
    await s.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key,67))"),
        {"key": "server-mail:" + str(finding["server_id"])},
    )
    params = {"user": owner, "server": finding["server_id"], "correlation": event["correlation_id"]}
    r = await one(
        s,
        "SELECT id FROM automation.mail_reports WHERE user_id=:user AND scan_server_id"
        "=:server AND correlation_id=:correlation",
        **params,
    )
    if r is None:
        r = await one(
            s,
            "SELECT id FROM automation.mail_reports WHERE user_id=:user AND scan_serve"
            "r_id=:server AND state='scanning' ORDER BY created_at LIMIT 1",
            user=owner,
            server=finding["server_id"],
        )
    if r is None:
        r = await one(
            s,
            "INSERT INTO automation.mail_reports(user_id,origin,scan_server_id,correla"
            "tion_id,state) VALUES(:user,'scan',:server,:correlation,'scanning') RETUR"
            "NING id",
            **params,
        )
    assert r
    await s.execute(
        text(
            "INSERT INTO automation.mail_report_contexts(report_id,correlation_id) VAL"
            "UES(:id,:correlation) ON CONFLICT DO NOTHING"
        ),
        {"id": r["id"], "correlation": event["correlation_id"]},
    )
    await s.execute(
        text("""
INSERT INTO automation.mail_report_servers(report_id,server_id,snapshot_id)
SELECT :id,server_id,snapshot_id FROM inventory.server_current_snapshots WHERE server_id=:server
ON CONFLICT DO NOTHING
"""),
        {"id": r["id"], "server": finding["server_id"]},
    )


async def busy(s: AsyncSession, report: dict[str, Any]) -> str | None:
    # All pages, parallel matching workers and finding publications must commit
    # before a report is prepared. Failed scans never produce a partial report.
    row = await one(s, "SELECT automation.mail_report_barrier(:id) AS value", id=report["id"])
    assert row
    state = row["value"]
    return "scan_running" if state["busy"] else "scan_failed" if state["failed"] else None


async def maintain(s: AsyncSession, correlation: UUID) -> int:
    await s.execute(text("SELECT automation.report_weekly_tick()"))
    pending = await rows(
        s,
        "SELECT * FROM automation.mail_reports WHERE state='scanning' ORDER BY created"
        "_at,id LIMIT 100 FOR UPDATE SKIP LOCKED",
    )
    rule = await one(
        s,
        "SELECT * FROM automation.notification_rules WHERE rule_key=CAST(:key AS uuid)"
        " ORDER BY version DESC LIMIT 1",
        key=RULE_KEY,
    )
    template = await one(
        s,
        "SELECT id FROM automation.notification_templates WHERE name='digest' AND lang"
        "uage='de' ORDER BY version DESC LIMIT 1",
    )
    assert rule and template
    total = 0
    for report in pending:
        reason = await busy(s, report)
        if reason == "scan_running":
            continue
        user = await one(
            s,
            "SELECT u.id,u.status,u.email,p.config,automation.personal_mail(u.id) AS m"
            "ail_config FROM security.users u LEFT JOIN automation.notification_prefer"
            "ences p ON p.user_id=u.id WHERE u.id=:id",
            id=report["user_id"],
        )
        prefs = Preferences.model_validate(user["config"] or {}) if user else Preferences()
        if (
            reason
            or not user
            or user["status"] != "active"
            or (report["origin"] != "manual" and not prefs.enabled)
        ):
            await s.execute(
                text(
                    "UPDATE automation.mail_reports SET state=:state,error_code=:error"
                    ",completed_at=clock_timestamp() WHERE id=:id"
                ),
                {
                    "id": report["id"],
                    "state": "failed" if reason else "cancelled",
                    "error": reason or "recipient_disabled",
                },
            )
            continue
        addresses = destinations(user["mail_config"], user["email"])
        if not addresses or not all(address(a, []) for a in addresses):
            await s.execute(
                text(
                    "UPDATE automation.mail_reports SET state='failed',error_code='inv"
                    "alid_recipient_address' WHERE id=:id"
                ),
                {"id": report["id"]},
            )
            continue
        notification = await insert(
            s,
            event=None,
            finding=None,
            user=report["user_id"],
            rule_row=rule,
            template=template["id"],
            status="ready",
            reason="server_scan_complete",
            due=datetime.now(UTC),
            correlation=report["correlation_id"],
        )
        await s.execute(
            text(
                "UPDATE automation.mail_reports SET state='ready',notification_id=:not"
                "ification,completed_at=clock_timestamp() WHERE id=:id"
            ),
            {"id": report["id"], "notification": notification},
        )
        total += 1
    return total


def threat(finding: dict[str, Any]) -> str:
    basis = finding.get("priority_basis") or {}
    if basis.get("kev_status") == "present" and basis.get("kev_is_current"):
        return "Kritisch (aktiv ausgenutzt, CISA KEV)"
    return {
        "critical": "Kritisch",
        "high": "Hoch",
        "medium": "Mittel",
        "low": "Niedrig",
        "unrated": "Unbekannt",
    }.get(finding["current_priority"], "Unbekannt")


async def content(
    s: AsyncSession, notification: UUID, user: UUID, prefs: Preferences
) -> tuple[list[tuple[str, str]], str, bool] | None:
    report = await one(
        s,
        "SELECT * FROM automation.mail_reports WHERE notification_id=:id AND user_id=:user",
        id=notification,
        user=user,
    )
    if report is None:
        return None
    if await busy(s, report):
        return [], "scan_not_complete", False
    if report["origin"] != "manual" and not prefs.enabled:
        return [], "recipient_disabled", False
    servers = await rows(
        s,
        """
SELECT srv.id,srv.display_name,r.snapshot_id,c.snapshot_id AS current_snapshot,snap.captured_at
FROM automation.mail_report_servers r JOIN inventory.servers srv ON srv.id=r.server_id
LEFT JOIN inventory.server_current_snapshots c ON c.server_id=srv.id
LEFT JOIN inventory.snapshots snap ON snap.id=c.snapshot_id
WHERE r.report_id=:report AND automation.report_server_access(:user,srv.id)
AND (:origin<>'scan' OR srv.created_by=:user)
ORDER BY srv.display_name,srv.id
""",
        report=report["id"],
        user=user,
        origin=report["origin"],
    )
    if report["origin"] == "scan" and not servers:
        return [], "recipient_not_authorized", False
    lines: list[tuple[str, str]] = []
    for server in servers:
        # Current ACLs are checked again before rendering any finding details.
        findings = await rows(
            s,
            "SELECT f.* FROM findings.current_findings f WHERE f.server_id=:server AND"
            " f.status IN ('open','in_progress') ORDER BY CASE f.current_priority WHEN"
            " 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THE"
            "N 3 ELSE 4 END,f.cve_id LIMIT 10001",
            server=server["id"],
        )
        if len(findings) > 10000:
            return [], "report_size_limit", False
        lines.append(
            (
                "unrated",
                f"Server: {server['display_name']} | Aktuelle Schwachstellen: {len(findings)}",
            )
        )
        if server["captured_at"]:
            lines.append(("unrated", f"Inventarstand: {server['captured_at'].isoformat()}"))
        if not server["current_snapshot"]:
            lines.append(
                (
                    "unrated",
                    "Noch kein Inventar vorhanden; ein Scan ist erst nach der Datenerf"
                    "assung möglich.",
                )
            )
        elif not findings:
            lines.append(("unrated", "Keine aktuellen Findings vorhanden."))
        for f in findings:
            basis = f.get("priority_basis") or {}
            cvss = basis.get("cvss") or {}
            epss = basis.get("epss") or {}
            probability = (
                f"{float(epss['score']) * 100:.2f} %"
                if epss.get("score") is not None and not epss.get("is_stale", True)
                else "Unbekannt"
            )
            lines.append(
                (
                    "unrated",
                    f"{f['cve_id']} | Betroffen | Bedrohung: {threat(f)} | "
                    f"CVSS: {cvss.get('base_score', cvss.get('calculated_score', 'Unbekannt'))} | "
                    f"EPSS: {probability}",
                )
            )
    if not servers:
        lines.append(("unrated", "Derzeit sind keine verwalteten Server vorhanden."))
    subject = (
        ("Serverscan: " + servers[0]["display_name"])
        if report["origin"] == "scan"
        else f"CVE Monitor: Wochenbericht für {len(servers)} Server"
    )
    return (
        lines,
        "".join(c for c in subject if ord(c) >= 32 and ord(c) != 127)[:160],
        report["origin"] == "manual",
    )


def render_report(mail: Any, subject: str, lines: list[str], base: str) -> bool:
    """Keep normal reports readable and preserve every CVE in large reports."""
    import html
    import io
    import zipfile

    from cve_notification.rendering import dashboard

    complete = subject + "\n\n" + "\n\n".join(lines) + "\n\n" + dashboard(base) + "/findings\n"
    attachment = None
    displayed = lines
    if len(complete.encode()) > 180000:
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("cve-bericht.txt", complete)
        attachment = archive.getvalue()
        if len(attachment) > 600000:
            return False
        displayed = [line for line in lines if line.startswith("Server:")]
        displayed.append(
            "Der vollständige Bericht mit allen CVEs und Inventarständen ist im Anhang enthalten."
        )
    plain = subject + "\n\n" + "\n\n".join(displayed) + "\n\n" + dashboard(base) + "/findings\n"
    body = (
        "<h2>"
        + html.escape(subject)
        + "</h2>"
        + "".join(
            ("<h2>" + html.escape(line) + "</h2>")
            if line.startswith("Server:")
            else ("<p>" + html.escape(line) + "</p>")
            for line in displayed
        )
        + '<p><a href="'
        + html.escape(dashboard(base) + "/findings", quote=True)
        + '">Findings öffnen</a></p>'
    )
    mail.replace_header("Subject", subject)
    mail.clear_content()
    mail.set_content(plain)
    mail.add_alternative(body, subtype="html")
    if attachment is not None:
        mail.add_attachment(
            attachment, maintype="application", subtype="zip", filename="cve-bericht.zip"
        )
    return True
