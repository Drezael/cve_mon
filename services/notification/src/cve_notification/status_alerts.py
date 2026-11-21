"""Finite system alert bridge using Phase-19 intents, n8n, rate controls and SMTP adapter."""

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from cve_common.jobs.contracts import Payload
from pydantic import Field, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from cve_notification.contracts import STATUS_EVENTS, Preferences, Rule
from cve_notification.mail_settings import destinations
from cve_notification.repository import insert, one, rows
from cve_notification.rules import address, next_allowed, preference_reason


class Event(Payload):
    schema_version: Literal[1]
    incident_id: UUID
    entity_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,47}$")
    incident_version: int = Field(ge=1)
    state: Literal["unavailable", "healthy"]
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")


def accepts(rule: Rule, kind: str) -> bool:
    return bool(
        rule.enabled
        and kind in rule.event_types
        and rule.recipients == "administrators"
        and rule.mode == "immediate"
        and not rule.lifecycle
        and not rule.technical
        and not rule.kev_only
        and rule.minimum_cvss is None
        and rule.minimum_epss is None
    )


async def consume(s: AsyncSession, event: dict[str, Any], correlation: UUID) -> tuple[int, str]:
    kind = event["event_type"].rsplit(".", 1)[-1]
    try:
        payload = Event.model_validate(event["payload"])
    except ValidationError:
        return 0, "unsupported_status_event"
    if (
        event["source"] != "cve-status"
        or event["aggregate_type"] != "status_incident"
        or kind not in STATUS_EVENTS
        or event["schema_version"] != 1
        or event["aggregate_id"] != str(payload.incident_id)
        or event["aggregate_version"] != payload.incident_version
    ):
        return 0, "unsupported_status_event"
    incident = await one(s, "SELECT * FROM status.incidents WHERE id=:id", id=payload.incident_id)
    if (
        not incident
        or incident["entity_id"] != payload.entity_id
        or incident["version"] != payload.incident_version
        or (incident["state"] == "resolved") != (kind == "status_recovered")
    ):
        return 0, "stale_status_event"
    rules = await rows(
        s,
        (
            "SELECT * FROM (SELECT DISTINCT ON(rule_key) * FROM"
            " automation.notification_rules ORDER BY rule_key,v"
            "ersion DESC) r ORDER BY created_at DESC LIMIT 100"
        ),
    )
    template = await one(
        s,
        (
            "SELECT id FROM automation.notification_templates W"
            "HERE name='finding' AND language='de' ORDER BY ver"
            "sion DESC LIMIT 1"
        ),
    )
    if not template:
        return 0, "status_template_missing"
    users = await rows(
        s,
        (
            "SELECT u.id,u.email,p.config,automation.personal_mail(u.id) AS "
            "mail_config FROM security.users u"
            " LEFT JOIN automation.notification_preferences p O"
            "N p.user_id=u.id WHERE status.recipient(u.id) ORDE"
            "R BY u.id LIMIT 100"
        ),
    )
    total = 0
    now = datetime.now(UTC)
    for row in rules:
        rule = Rule.model_validate(row["config"])
        if not accepts(rule, kind):
            continue
        for user in users:
            prefs = Preferences.model_validate(user["config"] or {})
            pseudo = {"current_priority": "critical"}
            reason = preference_reason(rule, prefs, kind, pseudo)
            if not all(
                address(item, rule.allowed_domains)
                for item in destinations(user["mail_config"], user["email"] or "")
            ):
                reason = "invalid_recipient_address"
            due = (
                now
                if rule.critical_bypass
                else max(next_allowed(now, rule.quiet), next_allowed(now, prefs.quiet))
            )
            await insert(
                s,
                event=event,
                finding=None,
                incident=payload.incident_id,
                user=user["id"],
                rule_row=row,
                template=template["id"],
                status="suppressed" if reason else "deferred" if due > now else "ready",
                reason=reason or "status_alert_authorized",
                due=due,
                correlation=correlation,
            )
            total += 1
    return total, "status_event_consumed"


async def dispatch_content(
    s: AsyncSession, n: dict[str, Any], user: UUID, rule: Rule, prefs: Preferences
) -> str | None:
    if not accepts(rule, n["kind"]) or not (
        await one(s, "SELECT status.recipient(:id) AS eligible", id=user) or {}
    ).get("eligible"):
        return None
    incident = await one(
        s,
        (
            "SELECT i.*,e.name FROM status.incidents i JOIN sta"
            "tus.entities e ON e.id=i.entity_id WHERE i.id=:id"
        ),
        id=n["status_incident_id"],
    )
    if (
        not incident
        or (incident["state"] == "resolved") != (n["kind"] == "status_recovered")
        or preference_reason(rule, prefs, n["kind"], {"current_priority": "critical"})
    ):
        return None
    label = (
        "Wiederherstellung bestätigt"
        if incident["state"] == "resolved"
        else "Dienst nicht verfügbar"
    )
    return f"Systemstatus: {label} | {incident[('name')]} | Grundcode: {
        incident[('reason_code')]
    } | Beginn: {incident[('opened_at')].isoformat()}"
