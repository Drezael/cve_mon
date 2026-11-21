"""Consumer marker and database effect participate in the caller's transaction."""

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def begin_consume(
    session: AsyncSession, consumer: str, event_id: UUID, fingerprint: bytes | None = None
) -> bool:
    return bool(
        (
            await session.execute(
                text("SELECT automation.consume_event(:consumer,:id,:fingerprint)"),
                {"consumer": consumer, "id": event_id, "fingerprint": fingerprint},
            )
        ).scalar_one()
    )
