"""Queue backpressure and shutdown must not leave producers or byte reservations stranded."""

import asyncio
from typing import cast

import pytest
from cve_common.database.engine import Database
from cve_common.jobs.errors import JobError
from cve_common.jobs.execution import ExecutionContext
from cve_enricher.contracts import Configuration, Result
from cve_enricher.pipeline import Entry, Pipeline


@pytest.mark.parametrize("cancel_waiter", [False, True])
async def test_full_queue_shutdown_releases_all_producers(
    monkeypatch: pytest.MonkeyPatch, cancel_waiter: bool
) -> None:
    monkeypatch.setattr("cve_enricher.pipeline.prepared_size", lambda _: 1)
    cfg = Configuration(prepared_queue_size=1)
    pipeline = Pipeline(cast(Database, None), cfg)
    blocked = asyncio.Event()

    async def commit(batch: list[Entry]) -> None:
        blocked.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(pipeline, "commit", commit)
    pipeline.start()
    context = cast(ExecutionContext, None)
    first = asyncio.create_task(pipeline.submit(context, []))
    await asyncio.wait_for(blocked.wait(), 1)
    second = asyncio.create_task(pipeline.submit(context, []))
    await asyncio.sleep(0)
    third = asyncio.create_task(pipeline.submit(context, []))
    await asyncio.sleep(0)
    assert pipeline.queue.qsize() == 1 and pipeline.bytes == 2
    assert not third.done()
    if cancel_waiter:
        third.cancel()
        await asyncio.gather(third, return_exceptions=True)
    await pipeline.close()
    results = await asyncio.wait_for(
        asyncio.gather(first, second, third, return_exceptions=True), 1
    )
    assert all(isinstance(value, (JobError, asyncio.CancelledError)) for value in results)
    assert pipeline.bytes == 0 and pipeline.queue.empty()
    await asyncio.wait_for(pipeline.queue.join(), 1)


async def test_byte_budget_applies_to_inflight_and_waiting_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    budget = 64 * 1024 * 1024
    monkeypatch.setattr("cve_enricher.pipeline.prepared_size", lambda _: budget)
    pipeline = Pipeline(cast(Database, None))
    blocked, release = asyncio.Event(), asyncio.Event()

    async def commit(batch: list[Entry]) -> None:
        blocked.set()
        await release.wait()
        for entry in batch:
            entry.future.set_result(Result())

    monkeypatch.setattr(pipeline, "commit", commit)
    pipeline.start()
    context = cast(ExecutionContext, None)
    first = asyncio.create_task(pipeline.submit(context, []))
    await asyncio.wait_for(blocked.wait(), 1)
    second = asyncio.create_task(pipeline.submit(context, []))
    await asyncio.sleep(0)
    assert pipeline.bytes == budget and pipeline.queue.empty() and not second.done()
    release.set()
    await asyncio.wait_for(asyncio.gather(first, second), 1)
    assert pipeline.bytes == 0
    await pipeline.close()
