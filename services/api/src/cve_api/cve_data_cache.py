"""Short shared snapshots of public feed statistics; never cache browser authorization."""

import asyncio
from collections.abc import Callable
from copy import deepcopy
from time import monotonic
from typing import Any

from cve_common.database.queries import one
from sqlalchemy.ext.asyncio import AsyncSession


class SnapshotCache:
    def __init__(self, *, clock: Callable[[], float] = monotonic) -> None:
        self.clock = clock
        self.lock = asyncio.Lock()
        self.value: dict[str, Any] | None = None
        self.expires = 0.0
        self.generation = 0

    def invalidate(self) -> None:
        self.generation += 1
        self.expires = 0.0

    async def get(self, session: AsyncSession) -> dict[str, Any]:
        async with self.lock:
            if self.value is not None and self.clock() < self.expires:
                return deepcopy(self.value)
            generation = self.generation
            value = await one(
                session,
                "SELECT cve.dashboard_data_status() AS value,"
                "cve.dashboard_pipeline_status() AS pipeline",
            )
            assert value is not None
            if generation == self.generation:
                self.value = value
                self.expires = self.clock() + 5
            return deepcopy(value)
