"""Explicit transaction: commit on success, rollback including cancellation on failure."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession

from cve_common.database.engine import Database
from cve_common.database.sessions import session


@asynccontextmanager
async def transaction(database: Database) -> AsyncIterator[AsyncSession]:
    async with session(database) as current, current.begin():
        yield current
