"""Bound CPU work to live threads, including work whose awaiter was cancelled."""

import asyncio
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


class WorkBusy(RuntimeError):
    """No computation slot became available within the admission budget."""


class BoundedThreads:
    def __init__(self, concurrency: int = 2) -> None:
        self.slots = asyncio.Semaphore(concurrency)

    async def run(self, operation: Callable[..., T], *args: object) -> T:
        try:
            async with asyncio.timeout(0.25):
                await self.slots.acquire()
        except TimeoutError:
            raise WorkBusy("cpu_admission_limit") from None
        task = asyncio.create_task(asyncio.to_thread(operation, *args))

        def finished(result: asyncio.Task[T]) -> None:
            self.slots.release()
            if not result.cancelled():
                result.exception()  # Retrieve failures even after the caller was cancelled.

        task.add_done_callback(finished)
        return await asyncio.shield(task)
