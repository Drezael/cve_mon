"Fixed domain audit records and same-transaction outbox, without profile/secret values."

import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

from cve_common.events.contracts import EventEnvelope
from cve_common.events.outbox import Outbox
from cve_common.events.registry import EventDefinition, EventRegistry
from cve_common.jobs.contracts import Payload, correlation_uuid
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.repository import one


class Change(Payload):
    action: str
    actor_id: UUID
    target_id: UUID | None
    audit_id: UUID
    change_digest: str


async def record(
    session: AsyncSession,
    action: str,
    actor: UUID,
    target: UUID | None,
    details: dict[str, Any] | None = None,
    *,
    success: bool = True,
) -> None:
    cid = correlation_uuid()
    metadata = json.dumps(details or {}, default=str, sort_keys=True)
    if len(metadata.encode()) > 32768:
        raise ValueError("Bounded change metadata required")
    row = await one(
        session,
        "INSERT INTO security.audit_log(actor_user_id,action,object_type,o"
        "bject_id,request_id,outcome,metadata) "
        "VALUES(:actor,:action,'administration',:target,:cid,:outcome,CAST"
        "(:metadata AS jsonb)) RETURNING id",
        actor=actor,
        action="administration." + action,
        target=str(target) if target else None,
        cid=cid,
        outcome="success" if success else "denied",
        metadata=metadata,
    )
    assert row is not None
    if not success:
        return
    registry = EventRegistry()
    registry.register(EventDefinition("administration.changed", 1, "administration-api", Change))
    await Outbox(registry).emit(
        session,
        EventEnvelope(
            event_type="administration.changed",
            source="administration-api",
            aggregate_type="administration",
            aggregate_id=str(target or actor),
            aggregate_version=1,
            idempotency_key=str(uuid4()),
            correlation_id=cid,
            payload={
                "action": action,
                "actor_id": str(actor),
                "target_id": str(target) if target else None,
                "audit_id": str(row["id"]),
                "change_digest": "sha256:" + hashlib.sha256(metadata.encode()).hexdigest(),
            },
        ),
    )
