"""An independent session per context; read contexts roll back on exit."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession

from cve_common.database.engine import Database


@asynccontextmanager
async def session(database: Database) -> AsyncIterator[AsyncSession]:
    if database.sessions is None:
        raise RuntimeError("Database not initialized")
    async with database.sessions() as current:
        yield current
