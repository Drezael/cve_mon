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
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker
from cve_common.lifecycle.resources import Resources
from cve_common.logging.setup import configure_logging
from fastapi import FastAPI, Request
from sqlalchemy import text
from starlette.responses import JSONResponse, Response

from cve_importer.contracts import Configuration, ImportSettings
from cve_importer.service import Service, proof
from cve_importer.transport import Transport, private


class Repository(JobRepository):
    def __init__(self, service: Service, settings: ImportSettings) -> None:
        super().__init__(service.database, service.registry())
        self.settings = settings

    async def claim(self, worker: UUID, lease: float) -> Job | None:
        if not proof(self.settings.egress_proof_file):
            return None
        return await super().claim(worker, lease)


def create_app(settings: ImportSettings | None = None) -> FastAPI:
    config = settings or load_settings(ImportSettings)
    raw_configuration = private(config.configuration_file)
    if len(raw_configuration) > 8192:
        raise ValueError("Source configuration too large")
    configuration = Configuration.model_validate_json(raw_configuration)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with Resources(config) as resources:
            assert resources.database is not None
            key_file = config.nvd_key_file
            if key_file is None and (config.configuration_file.parent / "nvd.key").exists():
                key_file = config.configuration_file.parent / "nvd.key"
            ca_file = config.external_ca_file
            if ca_file is None and (config.configuration_file.parent / "external-ca.crt").exists():
                ca_file = config.configuration_file.parent / "external-ca.crt"
            transport = Transport(
                configuration, config.scratch_directory, nvd_key_file=key_file, ca_file=ca_file
            )
            service = Service(resources.database, configuration, transport)
            transport.reserve = service.reserve
            worker = Worker(Repository(service, config), config)
            stop = asyncio.Event()
            task = asyncio.create_task(worker.run(stop))
            app.state.resources, app.state.worker, app.state.task = resources, worker, task
            try:
                yield
            finally:
                stop.set()
                await task
                await transport.close()

    app = FastAPI(
        title="CVE importer",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
        redirect_slashes=False,
    )
    app.add_middleware(
        TechnicalMiddleware, allowed_hosts=["cve-importer", "localhost", "127.0.0.1"]
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
            or request.app.state.task.done()
            or not worker.healthy
            or time.monotonic() - worker.last_tick > 10
            or not await request.app.state.resources.ready()
        ):
            return problem(503)
        return JSONResponse({"status": "ready"})

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        async with transaction(request.app.state.resources.database) as session:
            value = (await session.execute(text("SELECT cve.importer_metrics()"))).scalar_one()
        return JSONResponse(value)

    return app


def main() -> None:
    settings = load_settings(ImportSettings)
    configure_logging(settings.service_name, settings.log_level)
    uvicorn.run(
        "cve_importer.main:create_app",
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
