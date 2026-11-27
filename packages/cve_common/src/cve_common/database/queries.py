"""Small parameterized read helpers shared without importing a domain worker package."""

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def rows(s: AsyncSession, sql: str, **params: Any) -> list[dict[str, Any]]:
    return [dict(row) for row in (await s.execute(text(sql), params)).mappings().all()]


async def one(s: AsyncSession, sql: str, **params: Any) -> dict[str, Any] | None:
    values = await rows(s, sql, **params)
    return values[0] if values else None
