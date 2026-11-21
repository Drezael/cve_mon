"Explicit administrator-only credential registration, one-time issuance and revocation."

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request

from cve_api.auth.dependencies import csrf_for
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.authorization.dependencies import require_permission
from cve_api.authorization.principal import Principal
from cve_api.inventories.router import service_for
from cve_api.servers.schemas import Lifecycle

from .provisioning import Credentials
from .schemas import (
    CertificateCreate,
    CertificatePage,
    CertificateRead,
    ClientCreate,
    ClientPage,
    ClientRead,
    IssuedToken,
    TokenCreate,
    TokenPage,
    TokenRead,
    TokenRotate,
)

router = APIRouter(prefix="/api/v1/dashboard/admin", tags=["inventory-credentials"])


def service(request: Request) -> Credentials:
    return Credentials(service_for(request))


@router.get("/inventory-clients", response_model=ClientPage)
async def clients(
    request: Request, _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))]
) -> dict[str, Any]:
    return await service(request).listing(request.cookies.get(SESSION_COOKIE))


@router.post("/inventory-clients", status_code=201, response_model=ClientRead)
async def client(
    request: Request,
    body: ClientCreate,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).create(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), body
    )


@router.get("/inventory-clients/{client_id}/certificates", response_model=CertificatePage)
async def list_certificates(
    request: Request,
    client_id: UUID,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).listing(
        request.cookies.get(SESSION_COOKIE), client_id, "certificates"
    )


@router.post(
    "/inventory-clients/{client_id}/certificates", status_code=201, response_model=CertificateRead
)
async def create_certificates(
    request: Request,
    client_id: UUID,
    body: CertificateCreate,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).certificate(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), client_id, body
    )


@router.get("/inventory-clients/{client_id}/tokens", response_model=TokenPage)
async def list_tokens(
    request: Request,
    client_id: UUID,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).listing(request.cookies.get(SESSION_COOKIE), client_id, "tokens")


@router.post("/inventory-clients/{client_id}/tokens", status_code=201, response_model=IssuedToken)
async def create_tokens(
    request: Request,
    client_id: UUID,
    body: TokenCreate,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).issue(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), client_id, body
    )


@router.post("/inventory-clients/{client_id}/enable", response_model=ClientRead)
async def client_enable(
    request: Request,
    client_id: UUID,
    body: Lifecycle,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).client_status(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), client_id, True, body
    )


@router.post("/inventory-clients/{client_id}/disable", response_model=ClientRead)
async def client_disable(
    request: Request,
    client_id: UUID,
    body: Lifecycle,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).client_status(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), client_id, False, body
    )


@router.post("/inventory-tokens/{credential_id}/revoke", response_model=TokenRead)
async def token_revoke(
    request: Request,
    credential_id: UUID,
    body: Lifecycle,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).revoke(
        request.cookies.get(SESSION_COOKIE),
        csrf_for(request),
        "token",
        credential_id,
        body,
        disable=False,
    )


@router.post("/inventory-tokens/{credential_id}/disable", response_model=TokenRead)
async def token_disable(
    request: Request,
    credential_id: UUID,
    body: Lifecycle,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).revoke(
        request.cookies.get(SESSION_COOKIE),
        csrf_for(request),
        "token",
        credential_id,
        body,
        disable=True,
    )


@router.post("/inventory-certificates/{credential_id}/revoke", response_model=CertificateRead)
async def certificate_revoke(
    request: Request,
    credential_id: UUID,
    body: Lifecycle,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).revoke(
        request.cookies.get(SESSION_COOKIE),
        csrf_for(request),
        "certificate",
        credential_id,
        body,
        disable=False,
    )


@router.post("/inventory-tokens/{token_id}/rotate", status_code=201, response_model=IssuedToken)
async def token_rotate(
    request: Request,
    token_id: UUID,
    body: TokenRotate,
    _actor: Annotated[Principal, Depends(require_permission("server:acl:manage"))],
) -> dict[str, Any]:
    return await service(request).rotate(
        request.cookies.get(SESSION_COOKIE), csrf_for(request), token_id, body
    )
