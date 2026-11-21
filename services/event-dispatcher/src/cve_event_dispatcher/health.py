"""Liveness separate from database and processing-loop readiness."""

import time

from cve_common.http.responses import problem
from cve_common.lifecycle.resources import Resources
from fastapi import APIRouter, Request
from starlette.responses import JSONResponse, Response

from cve_event_dispatcher.dispatcher import Runtime

router = APIRouter()


@router.get("/health/live")
async def live() -> Response:
    return JSONResponse({"status": "alive"})


@router.get("/health/ready")
async def ready(request: Request) -> Response:
    resources: Resources = request.app.state.resources
    runtime: Runtime = request.app.state.runtime
    settings = runtime.dispatcher.settings
    loop = runtime.dispatcher
    if (
        not await resources.ready()
        or not loop.healthy
        or runtime.task is None
        or runtime.task.done()
        or time.monotonic() - loop.last_tick
        > max(5, settings.ready_timeout + settings.poll_seconds * 3 + 2)
    ):
        return problem(503)
    return JSONResponse({"status": "ready"})
