"Finite technical provisioning requests; no user roles, scopes or private key input."

from datetime import datetime
from uuid import UUID

from pydantic import Field, model_validator

from cve_api.servers.schemas import Lifecycle, Strict


class ClientCreate(Strict):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class CertificateCreate(Strict):
    certificate_pem: str = Field(min_length=1, max_length=6000, repr=False)
    chain_pem: str = Field(default="", max_length=6000, repr=False)


class TokenCreate(Strict):
    owner_user_id: UUID | None = None
    server_id: UUID | None = None
    certificate_id: UUID
    expires_at: datetime

    @model_validator(mode="after")
    def target(self) -> "TokenCreate":
        if (self.server_id is None) == (self.owner_user_id is None):
            raise ValueError("Select an owner for automatic discovery or a legacy server")
        return self


class TokenRotate(Lifecycle):
    certificate_id: UUID | None = None
    expires_at: datetime


class ClientRead(Strict):
    id: UUID
    name: str
    status: str
    created_at: datetime
    version: int


class CertificateRead(Strict):
    id: UUID
    principal_id: UUID
    not_before: datetime
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime
    fingerprint: str | None = None


class TokenRead(Strict):
    id: UUID
    principal_id: UUID
    server_id: UUID | None
    certificate_id: UUID
    scope: str
    status: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    disabled: bool
    last_used_at: datetime | None


class IssuedToken(TokenRead):
    token: str = Field(repr=False, pattern=r"^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$")
    one_time: bool


class ClientPage(Strict):
    items: list[ClientRead]
    limit: int


class CertificatePage(Strict):
    items: list[CertificateRead]
    limit: int


class TokenPage(Strict):
    items: list[TokenRead]
    limit: int
