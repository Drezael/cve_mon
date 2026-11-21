"""Private health HTTP and the registered Phase-7 PostgreSQL worker in one process."""

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from cve_common.config.validation import load_settings
from cve_common.database.transactions import transaction
from cve_common.http.errors import install_handlers
from cve_common.http.middleware import TechnicalMiddleware
from cve_common.http.responses import problem
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker
from cve_common.lifecycle.resources import Resources
from cve_common.logging.setup import configure_logging
from cve_common.workflows import centrally_controlled
from fastapi import FastAPI, Request
from sqlalchemy import text
from starlette.responses import JSONResponse, Response

from cve_inventory.processing import registry
from cve_inventory.settings import InventorySettings


class Repository(JobRepository):
    async def recover(self) -> int:
        async with transaction(self.database) as s:
            if not await centrally_controlled(s):
                await s.execute(text("SELECT inventory.backfill(100)"))
        return await super().recover()


def create_app(settings: InventorySettings | None = None) -> FastAPI:
    config = settings or load_settings(InventorySettings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with Resources(config) as resources:
            assert resources.database is not None
            worker = Worker(Repository(resources.database, registry()), config)
            stop = asyncio.Event()
            task = asyncio.create_task(worker.run(stop))
            app.state.resources, app.state.worker, app.state.task = resources, worker, task
            try:
                yield
            finally:
                stop.set()
                await task

    app = FastAPI(
        title="Inventory processor",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
        redirect_slashes=False,
    )
    app.add_middleware(
        TechnicalMiddleware, allowed_hosts=["cve-inventory", "localhost", "127.0.0.1"]
    )
    install_handlers(app)

    @app.get("/health/live")
    async def live() -> Response:
        return JSONResponse({"status": "alive"})

    @app.get("/health/ready")
    async def ready(request: Request) -> Response:
        worker: Worker = request.app.state.worker
        if (
            request.app.state.task.done()
            or not worker.healthy
            or time.monotonic() - worker.last_tick > 10
            or not await request.app.state.resources.ready()
        ):
            return problem(503)
        return JSONResponse({"status": "ready"})

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        database = request.app.state.resources.database
        async with transaction(database) as s:
            result = (await s.execute(text("SELECT inventory.processor_metrics()"))).scalar_one()
        return JSONResponse(result)

    return app


def main() -> None:
    settings = load_settings(InventorySettings)
    configure_logging(settings.service_name, settings.log_level)
    uvicorn.run(
        "cve_inventory.main:create_app",
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
