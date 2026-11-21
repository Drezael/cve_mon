"""Bounded parser-pool cleanup that survives task cancellation and reaps its children."""

import asyncio
from concurrent.futures import ProcessPoolExecutor
from contextlib import suppress


async def close_pool(pool: ProcessPoolExecutor, grace: float = 5) -> None:
    # Python 3.12 has no public terminate_workers(). Capture the owned processes
    # before shutdown clears _processes; never signal unrelated process groups.
    processes = list((getattr(pool, "_processes", None) or {}).values())

    async def cleanup() -> None:
        joined = asyncio.create_task(
            asyncio.to_thread(pool.shutdown, wait=True, cancel_futures=True)
        )
        try:
            await asyncio.wait_for(asyncio.shield(joined), grace)
        except TimeoutError:
            for process in processes:
                if process.is_alive():
                    process.terminate()
            for process in processes:
                await asyncio.to_thread(process.join, 0.2)
                if process.is_alive():
                    process.kill()
                    await asyncio.to_thread(process.join, 1)
            await asyncio.wait_for(asyncio.shield(joined), 2)
        finally:
            for process in processes:
                with suppress(ProcessLookupError):
                    if process.is_alive():
                        process.kill()
                        await asyncio.to_thread(process.join, 1)

    task = asyncio.create_task(cleanup())
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
    await task
    if cancelled:
        raise asyncio.CancelledError()
