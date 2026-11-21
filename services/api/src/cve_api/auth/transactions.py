"""Ordered security transactions; shared reads and exclusive account/permission mutations."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@asynccontextmanager
async def security_transaction(
    database: Database, *, mutation: bool = True
) -> AsyncIterator[AsyncSession]:
    async with transaction(database) as session:
        statement = (
            "SELECT pg_advisory_xact_lock(909001)"
            if mutation
            else "SELECT pg_advisory_xact_lock_shared(909001)"
        )
        await session.execute(text(statement))
        yield session
