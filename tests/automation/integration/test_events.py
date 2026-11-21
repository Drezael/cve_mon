"""Outbox atomicity, ordering, fencing, retries and exactly-once database consumer effects."""

import asyncio
from uuid import uuid4

import psycopg
import pytest
from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_common.events.contracts import EventEnvelope
from cve_common.events.delivery import DeliveryRepository
from cve_common.events.idempotency import begin_consume
from cve_common.events.outbox import Outbox
from cve_common.jobs.errors import ErrorCode
from cve_common.jobs.repository import JobRepository
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from scripts.database import manage as db
from tests.automation.integration.conftest import Lab, event_registry

pytestmark = [pytest.mark.automation, pytest.mark.security]


def event(**extra: object) -> EventEnvelope:
    return EventEnvelope.model_validate(
        {
            "event_type": "technical.event",
            "source": "technical-producer",
            "aggregate_type": "technical",
            "aggregate_id": uuid4().hex,
            "aggregate_version": 1,
            "idempotency_key": uuid4().hex,
            "payload": {"value": 1},
            **extra,
        }
    )


async def test_business_and_outbox_rollback_together(
    producer: JobRepository, automation_lab: Lab
) -> None:
    writer = Outbox(event_registry())
    envelope = event()
    identity = uuid4()
    with pytest.raises(RuntimeError):
        async with transaction(producer.database) as session:
            await session.execute(
                text("INSERT INTO automation.test_effects VALUES (:id,1)"), {"id": identity}
            )
            await writer.emit(session, envelope)
            raise RuntimeError("controlled rollback")
    with db.connect(automation_lab.config, "cve_migrator") as connection:
        connection.execute("SET ROLE postgres_owner")
        assert (
            connection.execute(
                "SELECT id FROM automation.event_outbox WHERE id=%s", (envelope.event_id,)
            ).fetchone()
            is None
        )
        assert (
            connection.execute(
                "SELECT id FROM automation.test_effects WHERE id=%s", (identity,)
            ).fetchone()
            is None
        )
    async with transaction(producer.database) as session:
        await session.execute(
            text("INSERT INTO automation.test_effects VALUES (:id,1)"), {"id": identity}
        )
        result = await writer.emit(session, envelope)
        assert result.event_id == envelope.event_id and result.occurred_at is not None
    async with transaction(producer.database) as session:
        duplicate = await writer.emit(session, envelope)
        assert duplicate.event_id == envelope.event_id


async def test_ordering_and_delivery_fencing(producer: JobRepository, automation_lab: Lab) -> None:
    writer = Outbox(event_registry())
    one = event()
    two = event(aggregate_id=one.aggregate_id, aggregate_version=2)
    for value in (one, two):
        async with transaction(producer.database) as session:
            await writer.emit(session, value)
    database = Database(automation_lab.settings("event_dispatcher"))
    database.open()
    repo = DeliveryRepository(database)
    try:
        first = None
        for _ in range(30):
            candidate = await repo.claim(["test_sink"], uuid4(), 2)
            assert candidate is not None
            if candidate.event_id == one.event_id:
                first = candidate
                break
            await repo.finish(candidate, "delivered")
        assert first is not None
        other = await repo.claim(["test_sink"], uuid4(), 2)
        assert other is None or other.event_id != two.event_id
        if other:
            await repo.finish(other, "delivered")
        assert not await repo.finish(first.model_copy(update={"lease_token": uuid4()}), "delivered")
        assert await repo.finish(first, "delivered")
        second = await repo.claim(["test_sink"], uuid4(), 2)
        assert second is not None and second.event_id == two.event_id
        assert await repo.finish(second, "retry", ErrorCode.TEMPORARY)
        await asyncio.sleep(0.25)
        retry = await repo.claim(["test_sink"], uuid4(), 2)
        assert retry is not None and retry.fencing_token > second.fencing_token
        assert not await repo.finish(second, "delivered")
        assert await repo.finish(retry, "delivered")
        assert not await repo.finish(retry, "delivered")
    finally:
        await database.close()


async def test_reordered_entity_version_rejected(producer: JobRepository) -> None:
    writer = Outbox(event_registry())
    one = event(aggregate_version=2)
    async with transaction(producer.database) as session:
        await writer.emit(session, one)
    with pytest.raises(DBAPIError):
        async with transaction(producer.database) as session:
            await writer.emit(session, event(aggregate_id=one.aggregate_id, aggregate_version=1))


async def test_parallel_consumers_single_effect_and_rollback(
    producer: JobRepository, worker: JobRepository
) -> None:
    envelope = event()
    writer = Outbox(event_registry())
    async with transaction(producer.database) as session:
        await writer.emit(session, envelope)
    identity = uuid4()
    with pytest.raises(RuntimeError):
        async with transaction(worker.database) as session:
            assert await begin_consume(session, "technical_consumer", envelope.event_id)
            await session.execute(
                text("INSERT INTO automation.test_effects VALUES (:id,1)"), {"id": identity}
            )
            raise RuntimeError("controlled failure")

    async def consume() -> bool:
        async with transaction(worker.database) as session:
            fresh = await begin_consume(session, "technical_consumer", envelope.event_id)
            if fresh:
                await session.execute(
                    text("INSERT INTO automation.test_effects VALUES (:id,1)"), {"id": identity}
                )
            return fresh

    results = await asyncio.gather(*(consume() for _ in range(8)))
    assert results.count(True) == 1
    with pytest.raises(DBAPIError):
        async with transaction(producer.database) as session:
            await begin_consume(session, "technical_consumer", envelope.event_id)
    with pytest.raises(DBAPIError):
        async with transaction(worker.database) as session:
            await begin_consume(session, "other_consumer", envelope.event_id)


async def test_metrics_and_no_group_writes(automation_lab: Lab) -> None:
    with db.connect(automation_lab.config, "status_probe") as connection:
        values = connection.execute("SELECT automation.runtime_metrics() AS values").fetchone()
        assert values is not None and "outbox_backlog" in values["values"]
    for role in ("importer", "event_dispatcher", "inventory_processor"):
        with (
            db.connect(automation_lab.config, role) as connection,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            connection.execute(
                "INSERT INTO inventory.server_groups(name) VALUES ('forbidden-runtime')"
            )


async def test_parallel_dispatcher_claims_are_distinct(
    producer: JobRepository, automation_lab: Lab
) -> None:
    writer = Outbox(event_registry())
    for _ in range(12):
        async with transaction(producer.database) as session:
            await writer.emit(session, event())
    database = Database(automation_lab.settings("event_dispatcher"))
    database.open()
    repository = DeliveryRepository(database)
    try:
        deliveries = await asyncio.gather(
            *(repository.claim(["test_sink"], uuid4(), 3) for _ in range(8))
        )
        nonempty = [d for d in deliveries if d is not None]
        assert len(nonempty) == 8 and len({(d.event_id, d.destination) for d in nonempty}) == 8
        assert all(await asyncio.gather(*(repository.finish(d, "delivered") for d in nonempty)))
    finally:
        await database.close()


async def test_explicit_delivery_recovery_preserves_attempt_counter(
    producer: JobRepository, automation_lab: Lab
) -> None:
    value = event()
    async with transaction(producer.database) as session:
        await Outbox(event_registry()).emit(session, value)
    database = Database(automation_lab.settings("event_dispatcher"))
    database.open()
    repository = DeliveryRepository(database)
    try:
        delivery = None
        for _ in range(100):
            candidate = await repository.claim(["test_sink"], uuid4(), 3)
            assert candidate is not None
            if candidate.event_id == value.event_id:
                delivery = candidate
                break
            await repository.finish(candidate, "delivered")
        assert delivery is not None
        assert await repository.finish(delivery, "failed", ErrorCode.PERMANENT)
        with (
            db.connect(automation_lab.config, "event_dispatcher") as connection,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            connection.execute(
                "SELECT automation.retry_delivery(%s,'test_sink')", (value.event_id,)
            )
        with db.connect(automation_lab.config, "api_security") as connection:
            connection.execute(
                "SELECT automation.retry_delivery(%s,'test_sink')", (value.event_id,)
            )
        restored = await repository.claim(["test_sink"], uuid4(), 3)
        assert restored is not None and restored.event_id == value.event_id
        assert (
            restored.attempts == delivery.attempts + 1
            and restored.fencing_token > delivery.fencing_token
        )
        assert await repository.finish(restored, "delivered")
    finally:
        await database.close()
