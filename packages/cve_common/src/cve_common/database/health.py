"""Minimal dependency probe with the service's own database identity."""

from cve_common.database.engine import Database


async def ready(database: Database, timeout: float) -> bool:
    return await database.ready(timeout)
