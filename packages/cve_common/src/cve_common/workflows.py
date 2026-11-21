"""Shared mode probe; business timers live in n8n when central control is enabled."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def centrally_controlled(session: AsyncSession) -> bool:
    return bool((await session.execute(text("SELECT automation.workflow_enabled()"))).scalar_one())
