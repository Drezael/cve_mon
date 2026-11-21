"Strict technical and dashboard HTTP entrances; shared validation/storage is in the service."

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Request, Response

from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.technical_auth.proxy_identity import proof

from .errors import UploadError
from .schemas import Receipt
from .service import InventoryService
from .transport import idempotency, media, multipart, read

router = APIRouter(tags=["inventory-acceptance"])


def service_for(request: Request) -> InventoryService:
    service = getattr(request.app.state, "inventory", None)
    if not isinstance(service, InventoryService):
        raise UploadError(503, "inventory_unavailable")
    return service


def receipt(response: Response, value: dict[str, Any]) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Location"] = value["status_url"]
    return value


@router.post(
    "/api/v1/inventories", status_code=202, response_model=Receipt, response_model_exclude_none=True
)
async def technical_upload(request: Request, response: Response) -> dict[str, Any]:
    service = service_for(request)
    context = proof(request, service.settings, service.gateway)
    async with service.admission(context.ip, "technical"):
        await service.technical_preflight(context)
        media(request, "application/json")
        key = idempotency(request)
        raw = await read(request, service.settings.max_bytes)
        value = await service.submit_technical(context, raw, key)
        return receipt(response, value)


@router.post(
    "/api/v1/dashboard/inventories/upload",
    status_code=202,
    response_model=Receipt,
    response_model_exclude_none=True,
)
async def dashboard_upload(request: Request, response: Response) -> dict[str, Any]:
    service = service_for(request)
    _, ip = transport(request)
    csrf = csrf_for(request)
    cookie = request.cookies.get(SESSION_COOKIE)
    async with service.admission(ip, "dashboard"):
        await service.dashboard_preflight(cookie, csrf)
        key = idempotency(request)
        async with multipart(request, service.settings) as (server, raw, metadata):
            value = await service.submit_dashboard(cookie, csrf, server, raw, key, metadata)
        return receipt(response, value)


@router.get(
    "/api/v1/inventories/submissions/{submission_id}",
    response_model=Receipt,
    response_model_exclude_none=True,
)
async def technical_status(
    request: Request, response: Response, submission_id: UUID
) -> dict[str, Any]:
    service = service_for(request)
    context = proof(request, service.settings, service.gateway)
    async with service.admission(context.ip, "status"):
        await service.technical_preflight(context)
        return receipt(response, await service.status_technical(context, submission_id))


@router.get(
    "/api/v1/dashboard/inventories/submissions/{submission_id}",
    response_model=Receipt,
    response_model_exclude_none=True,
)
async def dashboard_status(
    request: Request, response: Response, submission_id: UUID
) -> dict[str, Any]:
    service = service_for(request)
    _, ip = transport(request)
    async with service.admission(ip, "status"):
        return receipt(
            response,
            await service.status_dashboard(request.cookies.get(SESSION_COOKIE), submission_id),
        )
