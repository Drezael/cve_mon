"""Ordered security transactions; shared reads and exclusive account/permission mutations."""

import logging
import time
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
    acquired: float | None = None
    try:
        async with transaction(database) as session:
            statement = (
                "SELECT pg_advisory_xact_lock(909001)"
                if mutation
                else "SELECT pg_advisory_xact_lock_shared(909001)"
            )
            started = time.perf_counter()
            await session.execute(text(statement))
            logging.getLogger("cve.auth.locks").info(
                "security_lock_acquired",
                extra={"mutation": mutation, "wait_seconds": time.perf_counter() - started},
            )
            session.info["security_mutation"] = mutation
            acquired = time.perf_counter()
            yield session
    finally:
        if acquired is not None:
            logging.getLogger("cve.auth.locks").info(
                "security_transaction_finished",
                extra={
                    "mutation": mutation,
                    "duration_ms": (time.perf_counter() - acquired) * 1000,
                },
            )
