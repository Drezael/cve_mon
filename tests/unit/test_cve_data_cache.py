"""Concurrent readers share bounded public snapshots, never mutable caller projections."""

import asyncio
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from cve_api import cve_data_cache
from sqlalchemy.ext.asyncio import AsyncSession


async def test_parallel_statistics_are_computed_once_and_copies_are_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def read(*_args: object) -> dict[str, Any]:
        await asyncio.sleep(0.01)
        return {"value": {"record_count": 12}, "pipeline": {"outstanding": 4}}

    loader = AsyncMock(side_effect=read)
    monkeypatch.setattr(cve_data_cache, "one", loader)
    cache = cve_data_cache.SnapshotCache()
    session = cast(AsyncSession, object())
    values = await asyncio.gather(*(cache.get(session) for _ in range(16)))
    assert loader.await_count == 1
    values[0]["value"]["record_count"] = -1
    assert values[1]["value"]["record_count"] == 12
    assert (await cache.get(session))["value"]["record_count"] == 12


async def test_expiry_and_committed_refresh_invalidate_statistics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [0.0]
    loader = AsyncMock(side_effect=[{"value": 1}, {"value": 2}, {"value": 3}])
    monkeypatch.setattr(cve_data_cache, "one", loader)
    cache = cve_data_cache.SnapshotCache(clock=lambda: now[0])
    session = cast(AsyncSession, object())
    assert await cache.get(session) == {"value": 1}
    now[0] = 4.9
    assert await cache.get(session) == {"value": 1}
    now[0] = 5.0
    assert await cache.get(session) == {"value": 2}
    cache.invalidate()
    assert await cache.get(session) == {"value": 3}


async def test_invalidation_during_read_does_not_cache_the_old_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started, release = asyncio.Event(), asyncio.Event()

    async def read(*_args: object) -> dict[str, Any]:
        started.set()
        await release.wait()
        return {"value": 1}

    loader = AsyncMock(side_effect=read)
    monkeypatch.setattr(cve_data_cache, "one", loader)
    cache = cve_data_cache.SnapshotCache()
    session = cast(AsyncSession, object())
    pending = asyncio.create_task(cache.get(session))
    await started.wait()
    cache.invalidate()
    release.set()
    await pending
    await cache.get(session)
    assert loader.await_count == 2


async def test_failed_statistics_do_not_poison_the_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    import pytest

    loader = AsyncMock(side_effect=[RuntimeError("database read failed"), {"value": 1}])
    monkeypatch.setattr(cve_data_cache, "one", loader)
    cache = cve_data_cache.SnapshotCache()
    session = cast(AsyncSession, object())
    with pytest.raises(RuntimeError):
        await cache.get(session)
    assert await cache.get(session) == {"value": 1}
