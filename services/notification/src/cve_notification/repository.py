"""All state changes have immutable history; PostgreSQL decides claims and deduplication."""

import json
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_notification.contracts import Rule


async def rows(s: AsyncSession, sql: str, **values: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in (await s.execute(text(sql), values)).mappings().all()]


async def one(s: AsyncSession, sql: str, **values: Any) -> dict[str, Any] | None:
    result = await rows(s, sql, **values)
    return result[0] if result else None


async def record(s: AsyncSession, identity: UUID, old: str | None, reason: str) -> None:
    await s.execute(
        text("SELECT automation.notification_record(:id,:old,:reason)"),
        {"id": identity, "old": old, "reason": reason},
    )


async def change(
    s: AsyncSession, n: dict[str, Any], status: str, reason: str, *, due: datetime | None = None
) -> None:
    await s.execute(
        text(
            "UPDATE automation.notification_intents SET status=:status,reason="
            ":reason,version=version+1,scheduled_at=coalesce(:due,scheduled_at"
            "),lease_owner=NULL,lease_until=NULL WHERE id=:id"
        ),
        {"id": n["id"], "status": status, "reason": reason, "due": due},
    )
    await record(s, n["id"], n["status"], reason)


async def enqueue(
    s: AsyncSession, kind: str, payload: dict[str, Any], key: str, correlation: UUID
) -> None:
    await s.execute(
        text(
            "SELECT automation.enqueue_job(:kind,1,CAST(:payload AS jsonb),:ke"
            "y,:correlation,0,NULL,NULL,3,'notifications',false)"
        ),
        {
            "kind": "notifications." + kind,
            "payload": json.dumps(payload, default=str),
            "key": key,
            "correlation": correlation,
        },
    )


async def insert(
    s: AsyncSession,
    *,
    event: dict[str, Any] | None,
    finding: dict[str, Any] | None,
    user: UUID,
    rule_row: dict[str, Any],
    template: UUID,
    status: str,
    reason: str,
    due: datetime,
    correlation: UUID,
    incident: UUID | None = None,
    digest: UUID | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> UUID:
    identity = uuid4()
    value = await one(
        s,
        (
            "INSERT INTO automation.notification_intents(id,event_id,finding_i"
            "d,status_incident_id,recipient_user_id,rule_id,template_id,kind,status,reason,schedu"
            "led_at,correlation_id,digest_id,window_start,window_end)\n    VALU"
            "ES(:id,:event,:finding,:incident,:user,:rule,:template,:kind,:status,:reaso"
            "n,:due,:correlation,:digest,:start,:end) ON CONFLICT DO NOTHING R"
            "ETURNING id"
        ),
        id=identity,
        event=event["id"] if event else None,
        finding=finding["id"] if finding else None,
        incident=incident,
        user=user,
        rule=rule_row["id"],
        template=template,
        kind=event["event_type"].rsplit(".", 1)[-1] if event else "digest",
        status=status,
        reason=reason,
        due=due,
        correlation=correlation,
        digest=digest,
        start=start,
        end=end,
    )
    if value:
        await record(s, identity, None, reason)
        return identity
    if event:
        existing = await one(
            s,
            (
                "SELECT id FROM automation.notification_intents WHERE event_id=:ev"
                "ent AND recipient_user_id=:user AND rule_id=:rule AND kind=:kind"
            ),
            event=event["id"],
            user=user,
            rule=rule_row["id"],
            kind=event["event_type"].rsplit(".", 1)[-1],
        )
    else:
        existing = await one(
            s,
            (
                "SELECT id FROM automation.notification_intents WHERE recipient_us"
                "er_id=:user AND rule_id=:rule AND kind='digest' AND window_start="
                ":start AND window_end=:end"
            ),
            user=user,
            rule=rule_row["id"],
            start=start,
            end=end,
        )
    assert existing
    return existing["id"]  # type: ignore[no-any-return]


async def rule_active(s: AsyncSession, rule_row: dict[str, Any]) -> bool:
    latest = await one(
        s,
        (
            "SELECT id,config FROM automation.notification_rules WHERE rule_ke"
            "y=:key ORDER BY version DESC LIMIT 1"
        ),
        key=rule_row["rule_key"],
    )
    return bool(
        latest and latest["id"] == rule_row["id"] and Rule.model_validate(latest["config"]).enabled
    )
