"""Atomic host discovery through a bounded database function; identity is never authorization."""

import json
from typing import Any
from uuid import UUID

from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.repository import one
from cve_api.inventories.errors import UploadError
from cve_api.inventories.parser import Validated
from cve_api.servers.schemas import Metadata


async def resolve(
    session: AsyncSession,
    value: Validated,
    actor: UUID,
    selected: UUID | None = None,
    principal: UUID | None = None,
) -> UUID:
    if value.host is None:
        if value.server_id is None or (selected is not None and value.server_id != selected):
            raise UploadError(422, "server_identity_mismatch")
        return value.server_id
    try:
        row = await one(
            session,
            "SELECT inventory.resolve_upload_host("
            "CAST(:host AS jsonb),:actor,:selected,:principal) AS id",
            host=json.dumps(value.host),
            actor=actor,
            selected=selected,
            principal=principal,
        )
    except DBAPIError as error:
        code = getattr(error.orig, "sqlstate", None)
        status = {"42501": 403, "P0002": 404, "23505": 409, "22023": 422}.get(str(code))
        if status:
            raise UploadError(
                status, "host_identity_conflict" if status == 409 else "server_not_available"
            ) from None
        raise
    assert row
    return UUID(str(row["id"]))


async def apply_metadata(
    session: AsyncSession, receipt: dict[str, Any], actor: UUID, metadata: Metadata
) -> None:
    try:
        await one(
            session,
            "SELECT inventory.apply_upload_metadata(:submission,:actor,"
            "CAST(:metadata AS jsonb),:duplicate)",
            submission=receipt["submission_id"],
            actor=actor,
            metadata=metadata.model_dump_json(),
            duplicate=receipt["duplicate"],
        )
    except DBAPIError as error:
        code = str(getattr(error.orig, "sqlstate", None))
        if code in {"42501", "23505"}:
            raise UploadError(
                409 if code == "23505" else 403,
                "server_metadata_conflict" if code == "23505" else "server_metadata_forbidden",
            ) from None
        raise
