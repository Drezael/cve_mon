"""Force deferred invariant evaluation before returning a successful mutation result."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def check_last_administrator(session: AsyncSession) -> None:
    await session.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
