"""Only implemented technical routes are registered."""

from cve_common.health.live import live
from cve_common.health.ready import ready
from fastapi import APIRouter, Request
from starlette.responses import Response

from cve_api.dependencies import resources_for

router = APIRouter()


@router.get("/health/live", include_in_schema=False)
async def liveness(_request: Request) -> Response:
    return live("cve-api")


@router.get("/health/ready", include_in_schema=False)
async def readiness(request: Request) -> Response:
    auth = getattr(request.app.state, "auth", None)
    if auth is not None and not await auth.ready():
        from cve_common.http.responses import problem

        return problem(503)
    inventory = getattr(request.app.state, "inventory", None)
    if inventory is not None and not await inventory.ready():
        from cve_common.http.responses import problem

        return problem(503)
    return await ready(resources_for(request))
