"""One unprivileged HTTP/dispatcher process with a closed-by-default destination registry."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from cve_common.config.validation import load_settings
from cve_common.http.errors import install_handlers
from cve_common.http.middleware import TechnicalMiddleware
from cve_common.lifecycle.resources import Resources
from cve_common.logging.setup import configure_logging
from fastapi import FastAPI

from cve_event_dispatcher.dispatcher import Runtime
from cve_event_dispatcher.health import router as health
from cve_event_dispatcher.metrics import router as metrics
from cve_event_dispatcher.settings import DispatcherSettings


def create_app() -> FastAPI:
    settings = load_settings(DispatcherSettings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with Resources(settings) as resources:
            app.state.resources = resources
            runtime = Runtime(settings, resources)
            app.state.runtime = runtime
            try:
                runtime.start()
                yield
            finally:
                await runtime.close()

    app = FastAPI(
        title="CVE event dispatcher",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
        redirect_slashes=False,
    )
    app.add_middleware(
        TechnicalMiddleware, allowed_hosts=["cve-event-dispatcher", "localhost", "127.0.0.1"]
    )
    install_handlers(app)
    app.include_router(health)
    app.include_router(metrics)
    return app


def main() -> None:
    settings = load_settings(DispatcherSettings)
    configure_logging(settings.service_name, settings.log_level)
    uvicorn.run(
        "cve_event_dispatcher.main:create_app",
        factory=True,
        host="0.0.0.0",
        port=settings.http_port,
        workers=1,
        proxy_headers=False,
        access_log=False,
        server_header=False,
        log_config=None,
        timeout_graceful_shutdown=10,
        timeout_keep_alive=5,
        limit_concurrency=16,
    )


if __name__ == "__main__":
    main()
