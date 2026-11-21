"""Bounded handoff: original leased jobs durably own uncommitted prepared results."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_common.jobs.errors import ErrorCode, JobError, LeaseLost
from cve_common.jobs.execution import ExecutionContext
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_enricher.bulk import Prepared, prepared_size, publish
from cve_enricher.contracts import Configuration, Result
from cve_enricher.normalize import canonical


@dataclass
class Entry:
    context: ExecutionContext
    values: list[Prepared]
    future: asyncio.Future[Result]
    size: int
    count: int | None
    following: Callable[[AsyncSession], Awaitable[None]] | None


class Pipeline:
    """One writer per process; identity locks serialize overlapping publications.

    Queue contents are deliberately not acknowledged jobs. A crash replays the durable
    original job with its existing fencing token/lease recovery, recomputing preparation.
    """

    def __init__(self, database: Database, cfg: Configuration | None = None) -> None:
        self.database = database
        self.cfg = cfg or Configuration()
        self.queue: asyncio.Queue[Entry] = asyncio.Queue(maxsize=self.cfg.prepared_queue_size)
        self.capacity = asyncio.Condition()
        self.bytes = 0
        self.closed = False
        self.task: asyncio.Task[None] | None = None
        self.batches = self.records = self.failures = self.writing = 0

    def start(self) -> None:
        self.task = asyncio.create_task(self.run(), name="enrichment-batch-writer")

    async def submit(
        self,
        context: ExecutionContext,
        values: list[Prepared],
        *,
        count: int | None = None,
        following: Callable[[AsyncSession], Awaitable[None]] | None = None,
    ) -> Result:
        size = prepared_size(values)
        future: asyncio.Future[Result] = asyncio.get_running_loop().create_future()
        # Consume a possible exception even if a cancelled producer no longer awaits this result.
        future.add_done_callback(lambda f: None if f.cancelled() else f.exception())
        async with self.capacity:
            await self.capacity.wait_for(
                lambda: (
                    self.closed
                    or (
                        not self.queue.full() and self.bytes + size <= self.cfg.prepared_queue_bytes
                    )
                )
            )
            if self.closed or self.task is None or self.task.done():
                raise JobError(ErrorCode.UNAVAILABLE)
            self.bytes += size
            self.queue.put_nowait(Entry(context, values, future, size, count, following))
        return await asyncio.shield(future)

    async def commit(self, batch: list[Entry]) -> None:
        async with transaction(self.database) as session:
            results = await publish(session, [v for e in batch for v in e.values])
            offset = 0
            resolved = []
            for entry in batch:
                result = Result(count=entry.count) if entry.count is not None else results[offset]
                offset += len(entry.values)
                entry.context.validate_result(result)
                if entry.following:
                    await entry.following(session)
                resolved.append(result)
            fences = [
                {
                    k: str(v) if k != "epoch" else v
                    for k, v in e.context.repository.fence(e.context.job).items()
                }
                for e in batch
            ]
            valid = (
                (
                    await session.execute(
                        text("""
SELECT automation.finish_job(d.id,d.worker,d.token,d.epoch,'succeeded',NULL,NULL)
FROM jsonb_to_recordset(CAST(:rows AS jsonb)) d(id uuid,worker uuid,token uuid,epoch bigint)
ORDER BY d.id
"""),
                        {"rows": canonical(fences)},
                    )
                )
                .scalars()
                .all()
            )
            if not all(valid):
                raise LeaseLost()
        # Acknowledge only after the transaction, including outbox and job success, committed.
        for entry, result in zip(batch, resolved, strict=True):
            entry.context.completed = True
            if not entry.future.done():
                entry.future.set_result(result)
        self.batches += 1
        self.records += len(results)

    async def flush(self, batch: list[Entry]) -> None:
        try:
            await self.commit(batch)
        except Exception as error:
            # Isolate stale leases/input snapshots and malformed jobs; healthy neighbours proceed.
            if len(batch) > 1:
                middle = len(batch) // 2
                await self.flush(batch[:middle])
                await self.flush(batch[middle:])
            else:
                self.failures += 1
                if not batch[0].future.done():
                    batch[0].future.set_exception(error)

    async def run(self) -> None:
        batch: list[Entry] = []
        try:
            while True:
                batch = [await self.queue.get()]
                # Short collection window, bounded by both records and serialized bytes.
                await asyncio.sleep(self.cfg.write_flush_seconds)
                size = batch[0].size
                while (
                    not self.queue.empty()
                    and sum(len(e.values) for e in batch) < self.cfg.write_batch_size
                    and size < 8 * 1024 * 1024
                ):
                    entry = self.queue.get_nowait()
                    batch.append(entry)
                    size += entry.size
                self.writing = sum(len(e.values) for e in batch)
                await self.flush(batch)
                async with self.capacity:
                    self.bytes -= sum(e.size for e in batch)
                    self.capacity.notify_all()
                for _ in batch:
                    self.queue.task_done()
                batch = []
                self.writing = 0
        finally:
            self.closed = True
            while not self.queue.empty():
                batch.append(self.queue.get_nowait())
            for entry in batch:
                if not entry.future.done():
                    entry.future.set_exception(JobError(ErrorCode.SHUTDOWN))
            async with self.capacity:
                self.bytes -= sum(e.size for e in batch)
                self.writing = 0
                for _ in batch:
                    self.queue.task_done()
                self.capacity.notify_all()

    async def close(self) -> None:
        self.closed = True
        async with self.capacity:
            self.capacity.notify_all()
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)

    def metrics(self) -> dict[str, int]:
        return {
            "queued_jobs": self.queue.qsize(),
            "queued_bytes": self.bytes,
            "writing_records": self.writing,
            "committed_batches": self.batches,
            "committed_records": self.records,
            "failed_jobs": self.failures,
        }
