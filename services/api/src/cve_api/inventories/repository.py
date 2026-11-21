"Shared immutable, actor-scoped idempotent storage; never snapshots or processing jobs."

from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

from cve_common.jobs.contracts import correlation_uuid
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.repository import execute, one

from .errors import UploadError
from .events import accepted
from .parser import Validated


@dataclass(frozen=True)
class Source:
    kind: Literal["ansible_api", "dashboard_file"]
    identity: UUID
    server_id: UUID | None
    user_id: UUID | None = None
    session_id: UUID | None = None
    token_id: UUID | None = None
    certificate_id: UUID | None = None
    fingerprint: bytes | None = None


FIELDS = (
    "id,inventory_id,server_id,source,source_identity,received_at,stat"
    "us,schema_version,collected_at,"
    "(SELECT monitoring_id FROM inventory.host_identities h "
    "WHERE h.server_id=inventory.submissions.server_id) AS monitoring_id"
)


def response(row: dict[str, Any], duplicate: bool = False) -> dict[str, Any]:
    path = (
        "/api/v1/inventories/submissions/"
        if row["source"] == "ansible_api"
        else "/api/v1/dashboard/inventories/submissions/"
    )
    return {
        **(
            {"monitoring_id": row["monitoring_id"]}
            if row.get("monitoring_id") and row["schema_version"] in {"1.2", "1.3"}
            else {}
        ),
        "submission_id": row["id"],
        "inventory_id": row["inventory_id"],
        "server_id": row["server_id"],
        "status": row["status"],
        "duplicate": duplicate,
        "source": row["source"],
        "received_at": row["received_at"],
        "status_url": path + str(row["id"]),
    }


async def store(
    s: AsyncSession, source: Source, value: Validated, raw: bytes, key: str
) -> dict[str, Any]:
    if value.server_id is not None and value.server_id != source.server_id:
        raise UploadError(422, "server_identity_mismatch")
    active = await one(s, "SELECT status FROM inventory.servers WHERE id=:id", id=source.server_id)
    if active is None:
        raise UploadError(404, "server_not_found")
    if active["status"] != "active":
        raise UploadError(409, "server_inactive")
    # Serialize this actor's idempotency context before any global inventory UUID check.
    import hashlib

    lock = int.from_bytes(
        hashlib.sha256(
            (source.kind + str(source.identity) + str(source.server_id) + key).encode()
        ).digest()[:8],
        "big",
        signed=True,
    )
    await execute(s, "SELECT pg_advisory_xact_lock(:lock)", lock=lock)
    old = await one(
        s,
        "SELECT " + FIELDS + ",canonical_sha256 FROM inventory.submissions WHERE source=:source"
        " AND source_identity=:identity AND server_id=:server AND idempote"
        "ncy_key=:key",
        source=source.kind,
        identity=source.identity,
        server=source.server_id,
        key=key,
    )
    if old:
        if bytes(old["canonical_sha256"]) != value.canonical_sha256:
            raise UploadError(409, "idempotency_conflict")
        return response(old, True)
    # The immutable inventory UUID cannot be rebound across server, actor or upload channel.
    await execute(
        s,
        "INSERT INTO inventory.submission_identities(inventory_id,server_i"
        "d,canonical_sha256) VALUES(:id,:server,:digest) ON CONFLICT(inven"
        "tory_id) DO NOTHING",
        id=value.inventory_id,
        server=source.server_id,
        digest=value.canonical_sha256,
    )
    identity = await one(
        s,
        "SELECT server_id,canonical_sha256 FROM inventory.submission_ident"
        "ities WHERE inventory_id=:id",
        id=value.inventory_id,
    )
    assert identity is not None
    if (
        identity["server_id"] != source.server_id
        or bytes(identity["canonical_sha256"]) != value.canonical_sha256
    ):
        raise UploadError(409, "inventory_conflict")
    row = await one(
        s,
        "INSERT INTO inventory.submissions(inventory_id,server_id,source,s"
        "ource_identity,actor_user_id,session_reference,technical_principa"
        "l_id,token_id,certificate_id,certificate_fingerprint,"
        "schema_version,collected_at,payload_json,payload_raw,payload_sha2"
        "56,canonical_sha256,idempotency_key,correlation_id) "
        "VALUES(:inventory,:server,:source,:identity,:user,:session_ref,:p"
        "rincipal,:token,:certificate,:fingerprint,:schema,:captured,CAST("
        ":payload AS jsonb),:raw,:digest,:canonical,:key,:cid) RETURNING " + FIELDS,
        inventory=value.inventory_id,
        server=source.server_id,
        source=source.kind,
        identity=source.identity,
        user=source.user_id,
        session_ref=source.session_id,
        principal=source.identity if source.kind == "ansible_api" else None,
        token=source.token_id,
        certificate=source.certificate_id,
        fingerprint=source.fingerprint,
        schema=value.schema_version,
        captured=value.collected_at,
        payload=value.canonical.decode("utf-8"),
        raw=raw,
        digest=value.payload_sha256,
        canonical=value.canonical_sha256,
        key=key,
        cid=correlation_uuid(),
    )
    assert row is not None
    await accepted(s, row["id"], source.server_id, source.kind, source.user_id)
    return response(row)
