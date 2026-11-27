"""Observable background loops and shutdown that drains every owned task."""

import asyncio
import logging
import time
from dataclasses import dataclass


@dataclass
class LoopHealth:
    last_tick: float = 0.0
    healthy: bool = True

    def tick(self) -> None:
        self.last_tick = time.monotonic()
        self.healthy = True

    def ready(self, task: asyncio.Task[None], budget: float) -> bool:
        return not task.done() and self.healthy and time.monotonic() - self.last_tick <= budget


async def drain_tasks(*tasks: asyncio.Task[None], timeout: float = 10) -> None:
    """Retrieve all failures, reap pending tasks, then report an unexpected failure."""
    _, pending = await asyncio.wait(tasks, timeout=timeout)
    for task in pending:
        task.cancel()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, Exception):
            logging.getLogger("cve.lifecycle").error(
                "maintenance_failed", extra={"error_class": type(result).__name__}
            )
    failure = next((r for r in results if isinstance(r, Exception)), None)
    if failure is not None:
        raise failure
