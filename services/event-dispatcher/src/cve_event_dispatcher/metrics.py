"""Aggregate metrics contain neither payloads, URLs nor credentials."""

from fastapi import APIRouter, Request

from cve_event_dispatcher.dispatcher import Runtime

router = APIRouter()


@router.get("/metrics")
async def metrics(request: Request) -> dict[str, object]:
    runtime: Runtime = request.app.state.runtime
    return await runtime.dispatcher.repository.metrics()
