"""Private findings health, metrics and existing fenced PostgreSQL workers."""

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

import uvicorn
from cve_common.config.validation import load_settings
from cve_common.database.transactions import transaction
from cve_common.health.ready import worker_ready as execution_ready
from cve_common.http.errors import install_handlers
from cve_common.http.middleware import TechnicalMiddleware
from cve_common.http.responses import problem
from cve_common.jobs.models import Job
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker
from cve_common.lifecycle.resources import Resources
from cve_common.lifecycle.tasks import LoopHealth, drain_tasks
from cve_common.logging.setup import configure_logging
from cve_common.workflows import centrally_controlled
from fastapi import FastAPI, Request
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import JSONResponse, Response

from cve_findings.contracts import Request as JobRequest
from cve_findings.contracts import Settings
from cve_findings.files import proof
from cve_findings.service import Service, enqueue


class Repository(JobRepository):
    def __init__(self, service: Service, settings: Settings) -> None:
        super().__init__(service.database, service.registry())
        self.settings = settings

    async def claim(self, worker: UUID, lease: float) -> Job | None:
        if not proof(self.settings.guard_proof_file):
            return None
        return await super().claim(worker, lease)


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or load_settings(Settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with Resources(config) as resources:
            assert resources.database is not None
            database = resources.database
            service = Service(database)
            worker = Worker(Repository(service, config), config)
            stop = asyncio.Event()
            task = asyncio.create_task(worker.run(stop))

            maintenance_health = LoopHealth()
            maintenance_health.tick()

            async def maintain() -> None:
                while not stop.is_set():
                    maintenance_health.last_tick = time.monotonic()
                    try:
                        await asyncio.wait_for(stop.wait(), timeout=config.maintenance_seconds)
                        break
                    except TimeoutError:
                        pass
                    if not proof(config.guard_proof_file):
                        continue
                    try:
                        async with transaction(database) as session:
                            if await centrally_controlled(session):
                                maintenance_health.tick()
                                continue
                            present = (
                                await session.execute(
                                    text(
                                        "SELECT EXISTS(SELECT 1 FROM findings.findings "
                                        "WHERE model_version=2)"
                                    )
                                )
                            ).scalar_one()
                            if present:
                                slot = (
                                    await session.execute(
                                        text(
                                            "SELECT floor(extract(epoch FROM "
                                            "clock_timestamp())/:seconds)"
                                        ),
                                        {"seconds": config.maintenance_seconds},
                                    )
                                ).scalar_one()
                                await enqueue(
                                    session,
                                    "maintenance",
                                    JobRequest(),
                                    uuid4(),
                                    "findings-maintenance:" + str(slot),
                                )
                        maintenance_health.tick()
                    except (SQLAlchemyError, OSError, TimeoutError):
                        maintenance_health.healthy = False
                        logging.getLogger("cve.findings").error("dependency_unavailable")

            maintenance = asyncio.create_task(maintain())
            app.state.maintenance = maintenance
            app.state.maintenance_health = maintenance_health
            app.state.resources, app.state.worker, app.state.task = resources, worker, task
            try:
                yield
            finally:
                stop.set()
                await drain_tasks(task, maintenance)

    app = FastAPI(
        title="CVE findings",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
        redirect_slashes=False,
    )
    app.add_middleware(
        TechnicalMiddleware, allowed_hosts=["cve-findings", "localhost", "127.0.0.1"]
    )
    install_handlers(app)

    @app.get("/health/live")
    async def live() -> Response:
        return JSONResponse({"status": "alive"})

    @app.get("/health/ready")
    async def ready(request: Request) -> Response:
        worker: Worker = request.app.state.worker
        if not await execution_ready(
            request.app.state.resources,
            worker,
            request.app.state.task,
            guarded=proof(config.guard_proof_file),
        ) or not request.app.state.maintenance_health.ready(
            request.app.state.maintenance, 2 * config.maintenance_seconds + 10
        ):
            return problem(503)
        return JSONResponse({"status": "ready"})

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        async with transaction(request.app.state.resources.database) as session:
            value = (await session.execute(text("SELECT findings.metrics()"))).scalar_one()
        return JSONResponse(value)

    return app


def main() -> None:
    settings = load_settings(Settings)
    configure_logging(settings.service_name, settings.log_level)
    uvicorn.run(
        "cve_findings.main:create_app",
        factory=True,
        host="0.0.0.0",
        port=settings.http_port,
        workers=1,
        proxy_headers=False,
        access_log=False,
        server_header=False,
        log_config=None,
        timeout_graceful_shutdown=10,
        limit_concurrency=16,
    )


if __name__ == "__main__":
    main()
