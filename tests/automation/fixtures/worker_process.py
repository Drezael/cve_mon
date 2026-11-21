"""Only test code: a real process paused around a controlled database side effect."""

import asyncio
import json
import signal
import sys

from cve_common.database.engine import Database
from cve_common.jobs.contracts import Payload
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import JobDefinition, Registry
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker, WorkerSettings
from pydantic import BaseModel
from sqlalchemy import text


class Value(Payload):
    value: int


async def controlled(context: ExecutionContext, payload: BaseModel) -> None:
    async with context.atomic() as session:
        await session.execute(
            text(
                "INSERT INTO automation.test_effects(id,value) VALUES (:id,1) ON C"
                "ONFLICT DO NOTHING"
            ),
            {"id": context.job.id},
        )
    await asyncio.sleep(20)


async def main() -> None:
    data = json.load(sys.stdin)
    settings = WorkerSettings.model_validate(data["settings"])
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    database = Database(settings.database)
    database.open()
    registry = Registry()
    registry.register(JobDefinition("technical.slow", 1, Value, None, controlled, max_runtime=30))
    repository = JobRepository(database, registry)
    try:
        if data["mode"] == "before_handler":
            import uuid

            await repository.claim(uuid.uuid4(), settings.lease_seconds)
            await stop.wait()
        else:
            await Worker(repository, settings).run(stop)
    finally:
        await database.close()


if __name__ == "__main__":
    asyncio.run(main())
