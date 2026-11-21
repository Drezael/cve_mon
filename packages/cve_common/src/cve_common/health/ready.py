"""Dependency readiness is safe and distinct from process liveness."""

from starlette.responses import JSONResponse, Response

from cve_common.http.responses import problem
from cve_common.lifecycle.resources import Resources


async def ready(resources: Resources) -> Response:
    if not await resources.ready():
        return problem(503)
    return JSONResponse({"status": "ready"}, headers={"Cache-Control": "no-store"})
