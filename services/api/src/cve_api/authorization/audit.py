"""Separate actor/target, fixed actions, metadata allowlist and atomic transactional outbox."""

import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

from cve_common.events.contracts import EventEnvelope
from cve_common.events.outbox import Outbox
from cve_common.events.registry import EventDefinition, EventRegistry
from cve_common.jobs.contracts import Payload, correlation_uuid
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.repository import execute, one


class AdministrativeEvent(Payload):
    action: str
    actor_id: UUID | None
    target_id: UUID | None
    outcome: str
    reason: str | None = None
    audit_id: UUID | None = None
    change_digest: str | None = None


async def record(
    session: AsyncSession,
    action: str,
    actor: UUID | None,
    target: UUID | None = None,
    *,
    success: bool = True,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    cid = correlation_uuid()
    outcome = "success" if success else "denied"
    metadata = json.dumps(details or {}, default=str, ensure_ascii=True, sort_keys=True)
    if len(metadata.encode()) > 32768:
        raise ValueError("Bounded audit metadata required")
    audit = await one(
        session,
        "INSERT INTO security.audit_log(actor_user_id,action,object_type,object_id,"
        "request_id,outcome,auth_runtime,metadata) "
        "VALUES(:a,:action,'authorization',:target,:cid,:outcome,true,CAST(:m AS jsonb)) "
        "RETURNING id",
        a=actor,
        action="authorization." + action,
        target=str(target) if target else None,
        cid=cid,
        outcome=outcome,
        m=metadata,
    )
    assert audit is not None
    if target is not None:
        # Server/role UUIDs do not masquerade as target users in the FK-bound history.
        await execute(
            session,
            "INSERT INTO security.user_events(user_id,actor_user_id,event_type,auth_runtime) "
            "SELECT id,:a,:event,true FROM security.users WHERE id=:u",
            a=actor,
            event="authorization." + action,
            u=target,
        )
    registry = EventRegistry()
    registry.register(EventDefinition("authorization.security", 1, "cve-api", AdministrativeEvent))
    await Outbox(registry).emit(
        session,
        EventEnvelope(
            event_type="authorization.security",
            source="cve-api",
            aggregate_type="authorization",
            aggregate_id=str(target or actor or cid),
            aggregate_version=1,
            idempotency_key=str(uuid4()),
            correlation_id=cid,
            payload={
                "action": action,
                "actor_id": str(actor) if actor else None,
                "target_id": str(target) if target else None,
                "outcome": outcome,
                "reason": reason,
                "audit_id": str(audit["id"]),
                "change_digest": "sha256:" + hashlib.sha256(metadata.encode()).hexdigest(),
            },
        ),
    )
