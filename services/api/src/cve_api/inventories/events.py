"Atomic inventory audit/outbox; no payloads, bearer values or certificate bodies in events."

from typing import Any
from uuid import UUID, uuid4

from cve_common.events.contracts import EventEnvelope
from cve_common.events.outbox import Outbox
from cve_common.events.registry import EventDefinition, EventRegistry
from cve_common.jobs.contracts import Payload, correlation_uuid
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.repository import execute


class Accepted(Payload):
    submission_id: UUID
    server_id: UUID
    source: str


async def audit(
    session: AsyncSession,
    action: str,
    *,
    actor: UUID | None = None,
    target: UUID | None = None,
    details: dict[str, Any] | None = None,
    success: bool = True,
) -> None:
    import json

    await execute(
        session,
        "INSERT INTO security.audit_log(actor_user_id,action,object_type,o"
        "bject_id,request_id,outcome,metadata) "
        "VALUES(:actor,:action,'inventory_submission',:target,:cid,:outcom"
        "e,CAST(:metadata AS jsonb))",
        actor=actor,
        action="inventory." + action,
        target=str(target) if target else None,
        cid=correlation_uuid(),
        outcome="success" if success else "denied",
        metadata=json.dumps(details or {}, default=str),
    )


async def accepted(
    session: AsyncSession, sid: UUID, server: UUID, source: str, actor: UUID | None
) -> None:
    await audit(
        session,
        "accepted",
        actor=actor,
        target=sid,
        details={"server_id": server, "source": source},
    )
    event_type, origin = (
        ("inventory.accepted", "inventory-api")
        if source == "ansible_api"
        else ("inventory.dashboard_accepted", "cve-api")
    )
    registry = EventRegistry()
    registry.register(EventDefinition(event_type, 1, origin, Accepted))
    await Outbox(registry).emit(
        session,
        EventEnvelope(
            event_type=event_type,
            source=origin,
            aggregate_type="inventory_submission",
            aggregate_id=str(sid),
            aggregate_version=1,
            idempotency_key=str(uuid4()),
            correlation_id=correlation_uuid(),
            payload={"submission_id": str(sid), "server_id": str(server), "source": source},
        ),
    )
