"""Independent transactional delivery reservations and fencing."""

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_common.events.contracts import EventEnvelope
from cve_common.jobs.errors import ErrorCode, classify
from cve_common.jobs.worker import WorkerSettings
from cve_common.logging.correlation import correlation_id, request_id


class Delivery(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)
    event_id: UUID
    destination: str
    attempts: int
    lease_owner: UUID
    lease_token: UUID
    fencing_token: int

    def fence(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "destination": self.destination,
            "worker": self.lease_owner,
            "token": self.lease_token,
            "epoch": self.fencing_token,
        }


class DeliveryRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    async def claim(self, targets: list[str], worker: UUID, lease: float) -> Delivery | None:
        async with transaction(self.database) as session:
            row = (
                (
                    await session.execute(
                        text("SELECT * FROM automation.claim_delivery(:targets,:worker,:lease)"),
                        {"targets": targets, "worker": worker, "lease": lease},
                    )
                )
                .mappings()
                .first()
            )
            return Delivery.model_validate(dict(row)) if row else None

    async def event(self, delivery: Delivery) -> EventEnvelope:
        async with transaction(self.database) as session:
            row = (
                (
                    await session.execute(
                        text(
                            "SELECT * FROM automation.event_outbox WHERE id=:id AND runtime_ve"
                            "rsion=1"
                        ),
                        {"id": delivery.event_id},
                    )
                )
                .mappings()
                .one()
            )
            return EventEnvelope.model_validate(
                {**dict(row), "event_id": row["id"]}, extra="ignore"
            )

    async def heartbeat(self, delivery: Delivery, lease: float) -> bool:
        async with transaction(self.database) as session:
            return bool(
                (
                    await session.execute(
                        text(
                            "SELECT automation.heartbeat_delivery(:id,:destination,:worker,:to"
                            "ken,:epoch,:lease)"
                        ),
                        {**delivery.fence(), "lease": lease},
                    )
                ).scalar_one()
            )

    async def finish(
        self, delivery: Delivery, outcome: str, error: ErrorCode | None = None
    ) -> bool:
        async with transaction(self.database) as session:
            return bool(
                (
                    await session.execute(
                        text(
                            "SELECT automation.finish_delivery(:id,:destination,:worker,:token"
                            ",:epoch,:outcome,:error)"
                        ),
                        {
                            **delivery.fence(),
                            "outcome": outcome,
                            "error": error.value if error else None,
                        },
                    )
                ).scalar_one()
            )

    async def recover(self) -> int:
        async with transaction(self.database) as session:
            return int(
                (await session.execute(text("SELECT automation.recover_deliveries()"))).scalar_one()
            )

    async def metrics(self) -> dict[str, Any]:
        async with transaction(self.database) as session:
            return dict(
                (await session.execute(text("SELECT automation.runtime_metrics()"))).scalar_one()
            )


Transport = Callable[[EventEnvelope], Awaitable[None]]


class Dispatcher:
    def __init__(
        self,
        repository: DeliveryRepository,
        settings: WorkerSettings,
        transports: dict[str, Transport],
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.transports = dict(transports)
        self.id = uuid4()
        self.last_tick = 0.0
        self.healthy = False
        self.active: set[asyncio.Task[None]] = set()

    async def _heartbeat(self, delivery: Delivery, task: asyncio.Task[None]) -> None:
        try:
            while True:
                await asyncio.sleep(self.settings.heartbeat_seconds)
                if not await self.repository.heartbeat(delivery, self.settings.lease_seconds):
                    task.cancel()
                    return
        except SQLAlchemyError:
            self.healthy = False
            task.cancel()

    async def execute(self, delivery: Delivery) -> None:
        current = asyncio.current_task()
        assert current is not None
        heartbeat = asyncio.create_task(self._heartbeat(delivery, current))
        request_token = request_id.set(None)
        token = correlation_id.set(None)
        try:
            event = await self.repository.event(delivery)
            correlation_id.set(str(event.correlation_id))
            async with asyncio.timeout(30):
                await self.transports[delivery.destination](event)
            await self.repository.finish(delivery, "delivered")
            logging.getLogger("cve.events").info(
                "delivery_finished", extra={"event_id": str(event.event_id)}
            )
        except asyncio.CancelledError:
            try:
                await self.repository.finish(delivery, "retry", ErrorCode.SHUTDOWN)
            except SQLAlchemyError:
                self.healthy = False
        except Exception as error:
            failure = classify(error)
            try:
                await self.repository.finish(
                    delivery, "retry" if failure.retry else "failed", failure.code
                )
            except SQLAlchemyError:
                self.healthy = False
        finally:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)
            correlation_id.reset(token)
            request_id.reset(request_token)

    async def run(self, stop: asyncio.Event) -> None:
        try:
            while not stop.is_set():
                self.last_tick = time.monotonic()
                try:
                    await self.repository.recover()
                    self.healthy = True
                    for _ in range(
                        0
                        if self.settings.paused
                        else min(
                            self.settings.batch_size, self.settings.concurrency - len(self.active)
                        )
                    ):
                        if stop.is_set():
                            break
                        delivery = await self.repository.claim(
                            list(self.transports), self.id, self.settings.lease_seconds
                        )
                        if delivery is None:
                            break
                        if stop.is_set():
                            await self.repository.finish(delivery, "retry", ErrorCode.SHUTDOWN)
                            break
                        task = asyncio.create_task(self.execute(delivery))
                        self.active.add(task)
                        task.add_done_callback(self.active.discard)
                except SQLAlchemyError:
                    self.healthy = False
                    logging.getLogger("cve.events").warning("worker_unavailable")
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), self.settings.poll_seconds)
        finally:
            if self.active:
                _, pending = await asyncio.wait(self.active, timeout=self.settings.shutdown_seconds)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            self.healthy = False
