"""Private importer health/metrics and explicitly registered PostgreSQL source workers."""

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

import uvicorn
from cve_common.config.validation import load_settings
from cve_common.database.transactions import transaction
from cve_common.http.errors import install_handlers
from cve_common.http.middleware import TechnicalMiddleware
from cve_common.http.responses import problem
from cve_common.jobs.models import Job
from cve_common.jobs.registry import Registry
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker
from cve_common.lifecycle.resources import Resources
from cve_common.logging.setup import configure_logging
from fastapi import FastAPI, Request
from sqlalchemy import text
from starlette.responses import JSONResponse, Response

from cve_enricher.contracts import Configuration, Settings
from cve_enricher.epss import Client
from cve_enricher.files import private, proof
from cve_enricher.pipeline import Pipeline
from cve_enricher.service import Service


class Repository(JobRepository):
    def __init__(self, service: Service, settings: Settings) -> None:
        super().__init__(service.database, service.registry())
        self.settings = settings
        epss = Registry()
        if service.cfg.epss_enabled:
            epss.register(self.registry.get("cve.epss.sync_daily", 1))
        self.epss = JobRepository(service.database, epss)

    async def claim(self, worker: UUID, lease: float) -> Job | None:
        if not proof(self.settings.egress_proof_file):
            return None
        # One daily feed must not wait behind hundreds of thousands of record updates.
        daily = await self.epss.claim(worker, lease)
        return daily if daily is not None else await super().claim(worker, lease)


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or load_settings(Settings)
    raw_configuration = private(config.configuration_file)
    if len(raw_configuration) > 8192:
        raise ValueError("Source configuration too large")
    configuration = Configuration.model_validate_json(raw_configuration)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with Resources(config) as resources:
            assert resources.database is not None
            ca_file = config.external_ca_file
            if ca_file is None and (config.configuration_file.parent / "external-ca.crt").exists():
                ca_file = config.configuration_file.parent / "external-ca.crt"
            transport = Client(configuration, config.scratch_directory, ca_file=ca_file)
            pipeline = Pipeline(resources.database, configuration)
            pipeline.start()
            app.state.pipeline = pipeline
            service = Service(resources.database, configuration, transport, pipeline)
            worker = Worker(Repository(service, config), config)
            stop = asyncio.Event()
            task = asyncio.create_task(worker.run(stop))
            app.state.resources, app.state.worker, app.state.task = resources, worker, task
            try:
                yield
            finally:
                stop.set()
                try:
                    await task
                finally:
                    await pipeline.close()
                    await transport.close()

    app = FastAPI(
        title="CVE enricher",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
        redirect_slashes=False,
    )
    app.add_middleware(
        TechnicalMiddleware, allowed_hosts=["cve-enricher", "localhost", "127.0.0.1"]
    )
    install_handlers(app)

    @app.get("/health/live")
    async def live() -> Response:
        return JSONResponse({"status": "alive"})

    @app.get("/health/ready")
    async def ready(request: Request) -> Response:
        worker: Worker = request.app.state.worker
        if (
            not proof(config.egress_proof_file)
            or request.app.state.pipeline.task.done()
            or request.app.state.task.done()
            or not worker.healthy
            or time.monotonic() - worker.last_tick > 10
            or not await request.app.state.resources.ready()
        ):
            return problem(503)
        return JSONResponse({"status": "ready"})

    @app.get("/metrics/writer")
    async def writer_metrics(request: Request) -> Response:
        return JSONResponse(request.app.state.pipeline.metrics())

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        async with transaction(request.app.state.resources.database) as session:
            value = (await session.execute(text("SELECT cve.enricher_metrics()"))).scalar_one()
        return JSONResponse({**value, "writer": request.app.state.pipeline.metrics()})

    return app


def main() -> None:
    settings = load_settings(Settings)
    configure_logging(settings.service_name, settings.log_level)
    uvicorn.run(
        "cve_enricher.main:create_app",
        factory=True,
        host="0.0.0.0",
        port=settings.http_port,
        workers=settings.processes,
        proxy_headers=False,
        access_log=False,
        server_header=False,
        log_config=None,
        timeout_graceful_shutdown=10,
        limit_concurrency=16,
    )


if __name__ == "__main__":
    main()
