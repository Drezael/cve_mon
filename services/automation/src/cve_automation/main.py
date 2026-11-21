"""Private health listener and the supervised n8n-authorized automation worker."""

import asyncio
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from cve_common.config.validation import load_settings
from cve_common.jobs.repository import JobRepository
from cve_common.jobs.worker import Worker
from cve_common.lifecycle.resources import Resources
from fastapi import FastAPI, HTTPException

from cve_automation.service import Service, Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or load_settings(Settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        async with Resources(config) as resources:
            assert resources.database
            service = Service(resources.database, config)
            worker = Worker(JobRepository(resources.database, service.registry()), config)
            stop = asyncio.Event()
            task = asyncio.create_task(worker.run(stop))
            app.state.task = task
            app.state.worker = worker
            try:
                yield
            finally:
                stop.set()
                await task

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @app.get("/health/ready")
    @app.get("/health/live")
    async def ready() -> dict[str, str]:
        task = getattr(app.state, "task", None)
        worker = getattr(app.state, "worker", None)
        if task is None or task.done() or worker is None or not worker.healthy:
            raise HTTPException(status_code=503, detail="worker_unavailable")
        return {"status": "ready"}

    return app


def main() -> None:
    config = load_settings(Settings)
    uvicorn.run(
        create_app(config),
        host="0.0.0.0",
        port=config.http_port,
        access_log=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
