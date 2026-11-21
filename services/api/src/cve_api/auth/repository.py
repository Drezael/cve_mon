"""One explicitly configured security pool; SQL never includes user-supplied identifiers."""

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def one(session: AsyncSession, statement: str, **parameters: object) -> dict[str, Any] | None:
    result = (await session.execute(text(statement), parameters)).mappings().first()
    return dict(result) if result is not None else None


async def execute(session: AsyncSession, statement: str, **parameters: object) -> None:
    await session.execute(text(statement), parameters)
