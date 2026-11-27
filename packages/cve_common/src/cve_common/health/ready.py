"""Dependency readiness is safe and distinct from process liveness."""

import asyncio
import time

from starlette.responses import JSONResponse, Response

from cve_common.http.responses import problem
from cve_common.jobs.worker import Worker
from cve_common.lifecycle.resources import Resources


async def worker_ready(
    resources: Resources, worker: Worker, task: asyncio.Task[None], *, guarded: bool
) -> bool:
    return bool(
        guarded
        and not task.done()
        and worker.healthy
        and time.monotonic() - worker.last_tick <= 10
        and await resources.ready()
    )


async def ready(resources: Resources) -> Response:
    if not await resources.ready():
        return problem(503)
    return JSONResponse({"status": "ready"}, headers={"Cache-Control": "no-store"})
