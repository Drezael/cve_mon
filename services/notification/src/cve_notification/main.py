"""Private findings health, metrics and existing fenced PostgreSQL workers."""

import asyncio
import logging
import ssl
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal
from uuid import UUID, uuid4

import httpx
import uvicorn
from cve_common.config.validation import load_settings
from cve_common.database.engine import Database
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

from cve_notification.contracts import Settings
from cve_notification.files import proof
from cve_notification.internal import install
from cve_notification.repository import enqueue
from cve_notification.service import Service


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
            control_password = config.configuration_dir / "workflow_control.password"
            control_database = None
            if control_password.exists():
                control_database = Database(
                    config.database.model_copy(
                        update={
                            "username": "workflow_control",
                            "password_file": control_password,
                            "pool_size": 2,
                            "max_overflow": 0,
                        }
                    )
                )
                control_database.open()
            app.state.control_database = control_database
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
                                        "SELECT EXISTS(SELECT 1 FROM automation.notificatio"
                                        "n_intents WHERE status IN ('ready','deferred','lea"
                                        "sed','submitting','retryable_failure'))"
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
                                    {},
                                    "notifications-maintenance:" + str(slot),
                                    uuid4(),
                                )
                        maintenance_health.tick()
                    except (SQLAlchemyError, OSError, TimeoutError):
                        maintenance_health.healthy = False
                        logging.getLogger("cve.notification").error("dependency_unavailable")

            maintenance = asyncio.create_task(maintain())
            app.state.maintenance = maintenance
            app.state.maintenance_health = maintenance_health
            from cve_notification.dispatch import Dispatch
            from cve_notification.orchestration import runtime
            from cve_notification.smtp import Adapter

            base = config.configuration_dir
            fixed = runtime(base)
            app.state.dispatch = Dispatch(
                database,
                Adapter(
                    ca=base / "smtp-ca.crt",
                    certificate=base / "smtp-client.crt",
                    key=base / "smtp-client.key",
                ),
                sender=fixed["sender"],
                base=fixed["dashboard"],
                relay_instance=fixed["relay_instance"],
                configuration_dir=base,
            )
            app.state.resources, app.state.worker, app.state.task = resources, worker, task
            try:
                yield
            finally:
                stop.set()
                try:
                    await drain_tasks(task, maintenance)
                finally:
                    if control_database is not None:
                        await control_database.close()

    app = FastAPI(
        title="CVE notifications",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
        redirect_slashes=False,
    )
    app.add_middleware(
        TechnicalMiddleware, allowed_hosts=["cve-notification", "localhost", "127.0.0.1"]
    )
    install_handlers(app)
    install(app, config)

    @app.get("/health/live")
    async def live() -> Response:
        return JSONResponse({"status": "alive"})

    @app.get("/health/worker")
    async def worker_ready(request: Request) -> Response:
        worker: Worker = request.app.state.worker
        if (
            not await execution_ready(
                request.app.state.resources,
                worker,
                request.app.state.task,
                guarded=proof(config.guard_proof_file),
            )
            or not request.app.state.maintenance_health.ready(
                request.app.state.maintenance, 2 * config.maintenance_seconds + 10
            )
            or (
                request.app.state.control_database is not None
                and not await request.app.state.control_database.ready(2)
            )
        ):
            return problem(503)
        return JSONResponse({"status": "ready"})

    @app.get("/health/n8n/{dimension}")
    async def n8n_health(dimension: Literal["live", "ready"]) -> Response:
        from cve_notification.health import n8n_probe

        return await n8n_probe(config.configuration_dir / "ca.crt", dimension)

    @app.get("/health/ready")
    async def ready(request: Request) -> Response:
        response = await worker_ready(request)
        if response.status_code != 200:
            return response
        n8n_ready = False
        smtp_tcp = False
        try:
            context = ssl.create_default_context(cafile=str(config.configuration_dir / "ca.crt"))
            async with httpx.AsyncClient(verify=context, trust_env=False, timeout=0.7) as client:
                upstream = await client.get("https://cve-n8n:5678/healthz/readiness")
                n8n_ready = upstream.status_code == 200
            async with asyncio.timeout(0.7):
                _, writer = await asyncio.open_connection("cve-mail-submit", 2525)
                writer.close()
                await writer.wait_closed()
                smtp_tcp = True
        except (OSError, TimeoutError, httpx.HTTPError):
            pass
        return JSONResponse(
            {
                "status": "ready" if n8n_ready and smtp_tcp else "dependency_unavailable",
                "n8n": n8n_ready,
                "smtp_tcp": smtp_tcp,
            },
            status_code=200 if n8n_ready and smtp_tcp else 503,
        )

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        async with transaction(request.app.state.resources.database) as session:
            value = (
                await session.execute(text("SELECT automation.notification_metrics()"))
            ).scalar_one()
        return JSONResponse(value)

    return app


def main() -> None:
    settings = load_settings(Settings)
    configure_logging(settings.service_name, settings.log_level)
    uvicorn.run(
        "cve_notification.main:create_app",
        factory=True,
        host="0.0.0.0",
        port=settings.http_port,
        workers=1,
        ssl_certfile=str(settings.configuration_dir / "notification.crt"),
        ssl_keyfile=str(settings.configuration_dir / "notification.key"),
        proxy_headers=False,
        access_log=False,
        server_header=False,
        log_config=None,
        timeout_graceful_shutdown=10,
        limit_concurrency=16,
    )


if __name__ == "__main__":
    main()
