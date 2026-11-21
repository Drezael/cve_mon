"""Outbox writer shares the business session, never commits or sends during write."""

import json

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_common.events.contracts import EventEnvelope
from cve_common.events.registry import EventRegistry


class Outbox:
    def __init__(self, registry: EventRegistry) -> None:
        self.registry = registry

    async def emit(self, session: AsyncSession, event: EventEnvelope) -> EventEnvelope:
        self.registry.validate(event.event_type, event.schema_version, event.source, event.payload)
        data = event.model_dump(exclude={"occurred_at"})
        data["payload"] = json.dumps(event.payload, allow_nan=False)
        row = (
            (
                await session.execute(
                    text(
                        "SELECT * FROM automation.emit_event(:event_id,:event_type,:schema_version,"
                        ":source,:aggregate_type,:aggregate_id,:aggregate_version,"
                        "CAST(:payload AS jsonb),:idempotency_key,:correlation_id)"
                    ),
                    data,
                )
            )
            .mappings()
            .one()
        )
        return EventEnvelope.model_validate({**dict(row), "event_id": row["id"]}, extra="ignore")
