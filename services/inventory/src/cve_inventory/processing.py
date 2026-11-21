"""One bounded, fenced business transaction; originals and administrative data stay intact."""

import hashlib
from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from cve_common.database.transactions import transaction
from cve_common.events.contracts import EventEnvelope
from cve_common.events.outbox import Outbox
from cve_common.events.registry import EventDefinition, EventRegistry
from cve_common.jobs.contracts import Payload
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import JobDefinition, Registry
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_inventory.normalization import NORMALIZER, PROCESSOR, encoded
from cve_inventory.validation import InvalidInventory, prepare


class Submission(Payload):
    submission_id: UUID


class Result(Payload):
    submission_id: UUID
    snapshot_id: UUID | None
    status: Literal["completed", "rejected_after_acceptance"]


class InventoryEvent(Payload):
    submission_id: UUID
    server_id: UUID
    snapshot_id: UUID | None
    normalizer_version: Literal["inventory-1"] = "inventory-1"
    collection_status: Literal["complete", "partial", "failed"] | None = None
    captured_at: datetime
    is_current: bool = False
    error_code: str | None = Field(default=None, pattern=r"^[a-z_]{1,64}$")


EVENTS = EventRegistry()
for _name in (
    "processing_started",
    "snapshot_created",
    "current_changed",
    "processing_completed",
    "processing_failed",
):
    EVENTS.register(EventDefinition("inventory." + _name, 1, "inventory-processor", InventoryEvent))
OUTBOX = Outbox(EVENTS)


async def emit(
    s: AsyncSession,
    kind: str,
    row: dict[str, Any],
    snapshot: UUID | None = None,
    *,
    current: bool = False,
    error: str | None = None,
) -> None:
    payload = InventoryEvent(
        submission_id=row["id"],
        server_id=row["server_id"],
        snapshot_id=snapshot,
        captured_at=row["collected_at"],
        collection_status=row["payload_json"].get("collection_status"),
        is_current=current,
        error_code=error,
    )
    identity = str(snapshot) if kind in {"snapshot_created", "current_changed"} else str(row["id"])
    await s.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key,14))"),
        {"key": kind + ":" + identity},
    )
    # Audit only when this logical event is first emitted, never on replay.
    exists = (
        await s.execute(
            text(
                "SELECT 1 FROM automation.event_outbox WHERE "
                "source='inventory-processor' AND idempotency_key=:key"
            ),
            {
                "key": kind
                + ":"
                + (
                    str(snapshot)
                    if kind in {"snapshot_created", "current_changed"}
                    else str(row["id"])
                )
            },
        )
    ).first()
    if not exists:
        await s.execute(
            text(
                "INSERT INTO "
                "security.audit_log(action,object_type,object_id,request_id,outcom"
                "e,metadata) "
                "VALUES(:action,'inventory_submission',:id,:cid,:outcome,CAST(:metadata AS jsonb))"
            ),
            {
                "action": "inventory." + kind,
                "id": str(row["id"]),
                "cid": row["correlation_id"],
                "outcome": "denied" if error else "success",
                "metadata": encoded(payload.model_dump(mode="json")),
            },
        )
    # Snapshot/current events are global across provenance receipts.
    await OUTBOX.emit(
        s,
        EventEnvelope(
            event_type="inventory." + kind,
            source="inventory-processor",
            aggregate_type="inventory",
            aggregate_id=identity,
            aggregate_version=1,
            idempotency_key=kind + ":" + identity,
            correlation_id=row["correlation_id"],
            payload=payload.model_dump(mode="json"),
        ),
    )


async def bulk(s: AsyncSession, sql: str, rows: list[dict[str, Any]]) -> None:
    for offset in range(0, len(rows), 500):
        await s.execute(text(sql), rows[offset : offset + 500])


async def persist(s: AsyncSession, row: dict[str, Any], data: dict[str, Any]) -> tuple[UUID, bool]:
    await s.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
        {"key": "inventory-identity:" + str(row["inventory_id"])},
    )
    existing = (
        (
            await s.execute(
                text(
                    "SELECT "
                    "id,server_id,schema_version,normalizer_version,submission_id,orig"
                    "inal_json "
                    "FROM inventory.snapshots WHERE inventory_id=:id"
                ),
                {"id": row["inventory_id"]},
            )
        )
        .mappings()
        .one_or_none()
    )
    if existing:
        if (
            existing["submission_id"] is None
            or existing["server_id"] != row["server_id"]
            or existing["schema_version"] != row["schema_version"]
            or existing["normalizer_version"] != NORMALIZER
            or existing["original_json"] != row["payload_json"]
        ):
            raise InvalidInventory("existing_inventory_conflict")
        return UUID(str(existing["id"])), False
    sid = uuid4()
    await s.execute(
        text(
            "INSERT INTO "
            "inventory.snapshots(id,inventory_id,server_id,schema_version,capt"
            "ured_at,received_at,"
            "collection_status,content_sha256,original_json,original_bytes,pro"
            "cessing_status,submission_id,"
            "normalizer_version,processor_version,package_count,service_count,"
            "container_count,image_count,quality,eligible)"
            " "
            "VALUES(:id,:inventory,:server,:schema,:captured,:received,:status"
            ",:hash,CAST(:json AS jsonb),:raw,"
            "'processing',:submission,:normalizer,:processor,:packages,:servic"
            "es,:containers,:images,CAST(:quality AS jsonb),:eligible)"
        ),
        {
            "id": sid,
            "inventory": row["inventory_id"],
            "server": row["server_id"],
            "schema": row["schema_version"],
            "captured": row["collected_at"],
            "received": row["received_at"],
            "status": row["payload_json"]["collection_status"],
            "hash": row["payload_sha256"],
            "json": encoded(row["payload_json"]),
            "raw": row["payload_raw"],
            "submission": row["id"],
            "normalizer": NORMALIZER,
            "processor": PROCESSOR,
            **{key: len(data[key]) for key in ("packages", "services", "containers", "images")},
            "quality": encoded(data["quality"]),
            "eligible": data["eligible"],
        },
    )
    os_data = data["os"]
    if os_data:
        await s.execute(
            text(
                "INSERT INTO "
                "inventory.operating_systems(snapshot_id,name,version,distribution"
                ",release,architecture,kernel_version,original_data)"
                " "
                "VALUES(:sid,:name,:version,:distribution,:release,:architecture,:"
                "kernel,CAST(:original AS jsonb))"
            ),
            {
                "sid": sid,
                "name": os_data.get("distribution", "unknown"),
                "version": os_data.get("release", "unknown"),
                "distribution": data["os_id"],
                "release": os_data.get("release"),
                "architecture": os_data.get("architecture"),
                "kernel": os_data.get("kernel"),
                "original": encoded(os_data),
            },
        )
    await s.execute(
        text(
            "INSERT INTO inventory.kernels "
            "VALUES(:sid,:version,:architecture,CAST(:hardware AS jsonb))"
        ),
        {
            "sid": sid,
            "version": data["kernel"]["version_raw"],
            "architecture": data["kernel"]["architecture"],
            "hardware": encoded(data["kernel"]["hardware"]),
        },
    )
    await bulk(
        s,
        "INSERT INTO "
        "inventory.packages(snapshot_id,name,version,architecture,package_"
        "manager,source_package,source_version,software_identity,"
        "original_data,record_sha256,epoch,upstream_version,release,normal"
        "ization_status) VALUES(:sid,:name,:version,:architecture,"
        ":package_manager,:source_package,:source_version,:software_identity,CAST(:origina"
        "l_data AS "
        "jsonb),:record_sha256,:epoch,:upstream_version,:release,:normaliz"
        "ation_status)",
        [{**p, "sid": sid, "original_data": encoded(p["original_data"])} for p in data["packages"]],
    )
    await bulk(
        s,
        "INSERT INTO "
        "inventory.services(snapshot_id,name,state,enabled,original_data,r"
        "ecord_number,manager) "
        "VALUES(:sid,:name,:state,:enabled,CAST(:original AS jsonb),:number,:manager)",
        [
            {
                "sid": sid,
                "name": p["name"],
                "state": p["state"],
                "enabled": p["enabled"],
                "original": encoded(p),
                "number": i,
                "manager": p.get("manager"),
            }
            for i, p in enumerate(data["services"])
        ],
    )
    await bulk(
        s,
        "INSERT INTO "
        "inventory.containers(snapshot_id,container_id,name,image_referenc"
        "e,image_digest,state,original_data,record_number,image_id,image_r"
        "esolved) "
        "VALUES(:sid,:cid,:name,:reference,:digest,:state,CAST(:original "
        "AS jsonb),:number,:image,:resolved)",
        [
            {
                "sid": sid,
                "cid": p["container_id"],
                "name": p.get("name"),
                "reference": p["image_reference"],
                "digest": p.get("image_digest"),
                "state": p["state"],
                "original": encoded({k: v for k, v in p.items() if k != "image_resolved"}),
                "number": i,
                "image": p.get("image_id"),
                "resolved": p["image_resolved"],
            }
            for i, p in enumerate(data["containers"])
        ],
    )
    await bulk(
        s,
        "INSERT INTO inventory.images VALUES(:sid,:image,CAST(:refs AS "
        "jsonb),CAST(:digests AS jsonb),:arch,:created,CAST(:original AS "
        "jsonb),CAST(:parts AS jsonb))",
        [
            {
                "sid": sid,
                "image": p["image_id"],
                "refs": encoded(p["references"]),
                "digests": encoded(p["repo_digests"]),
                "arch": p.get("architecture"),
                "created": datetime.fromisoformat(p["created_at"].replace("Z", "+00:00"))
                if p.get("created_at")
                else None,
                "original": encoded(p["original_records"]),
                "parts": encoded(p["reference_parts"]),
            }
            for p in data["images"]
        ],
    )
    bills: dict[bytes, dict[str, Any]] = {}
    links = []
    for number, entry in enumerate(data["container_software"]):
        document = entry.get("document")
        bill = hashlib.sha256(encoded(document).encode()).digest() if document else None
        if document and bill:
            bills[bill] = {"digest": bill, "doc": encoded(document), "n": len(document["packages"])}
        links.append(
            {
                "sid": sid,
                "number": number,
                "cid": entry["container_id"],
                "image": entry["image_id"],
                "scope": entry["scope"],
                "target": entry.get("target"),
                "status": entry["status"],
                "captured": datetime.fromisoformat(entry["captured_at"].replace("Z", "+00:00")),
                "error": entry.get("error_code"),
                "bill": bill,
            }
        )
    await bulk(
        s,
        "INSERT INTO inventory.software_bills VALUES(:digest,CAST(:doc AS jsonb),:n) "
        "ON CONFLICT DO NOTHING",
        list(bills.values()),
    )
    await bulk(
        s,
        "INSERT INTO inventory.container_software VALUES(:sid,:number,:cid,:image,:scope,"
        ":target,:status,:captured,:error,:bill)",
        links,
    )
    await bulk(
        s,
        "INSERT INTO inventory.collection_sections VALUES(:sid,:section,:status,:error_code)",
        [{**p, "sid": sid} for p in data["sections"]],
    )
    await s.execute(
        text(
            "UPDATE inventory.snapshots SET "
            "processing_status='processed',processed_at=clock_timestamp() "
            "WHERE id=:id"
        ),
        {"id": sid},
    )
    await emit(s, "snapshot_created", row, sid)
    changed = (
        await s.execute(text("SELECT inventory.select_current(:id)"), {"id": sid})
    ).scalar_one()
    if changed:
        await emit(s, "current_changed", row, sid, current=True)
    return sid, bool(changed)


async def handle(context: ExecutionContext, payload: BaseModel) -> Result:
    request = Submission.model_validate(payload.model_dump())
    async with transaction(context.repository.database) as s:
        stored = (
            (
                await s.execute(
                    text(
                        "SELECT s.*,h.monitoring_id AS host_monitoring_id "
                        "FROM inventory.submissions s "
                        "LEFT JOIN inventory.host_identities h ON h.server_id=s.server_id "
                        "WHERE s.id=:id"
                    ),
                    {"id": request.submission_id},
                )
            )
            .mappings()
            .one()
        )
        row = dict(stored)
    async with context.atomic() as s:
        await s.execute(
            text(
                "UPDATE inventory.submission_processing SET "
                "status='processing',job_id=:job,finished_at=NULL,error_code=NULL,"
                "started_at=COALESCE(started_at,clock_timestamp()) "
                "WHERE submission_id=:id AND status IN ('accepted','processing','failed')"
            ),
            {"id": row["id"], "job": context.job.id},
        )
        await emit(s, "processing_started", row)
    failure: str | None = None
    try:
        data = await prepare(row)
    except InvalidInventory as error:
        failure = str(error)
        data = {}

    async def commit(s: AsyncSession) -> Result:
        # Serialize inventory receipts before the current pointer; check the job fence last.
        if failure:
            await s.execute(
                text(
                    "UPDATE inventory.submission_processing SET status='rejected_after_acceptance',"
                    "finished_at=clock_timestamp(),error_code=:error WHERE "
                    "submission_id=:id AND snapshot_id IS NULL"
                ),
                {"id": row["id"], "error": failure},
            )
            await emit(s, "processing_failed", row, error=failure)
            return Result(
                submission_id=row["id"], snapshot_id=None, status="rejected_after_acceptance"
            )
        sid, _changed = await persist(s, row, data)
        await s.execute(
            text(
                "UPDATE inventory.submission_processing SET status='completed',snapshot_id=:sid,"
                "finished_at=clock_timestamp(),error_code=NULL WHERE submission_id=:id"
            ),
            {"id": row["id"], "sid": sid},
        )
        await emit(s, "processing_completed", row, sid)
        return Result(submission_id=row["id"], snapshot_id=sid, status="completed")

    try:
        result = await context.complete(commit)
    except InvalidInventory as error:
        # The first business transaction rolled back; record rejection with a fresh fence.
        failure = str(error)
        result = await context.complete(commit)
    assert isinstance(result, Result)
    return result


def registry() -> Registry:
    result = Registry()
    result.register(
        JobDefinition(
            "inventory.process_submission",
            1,
            Submission,
            Result,
            handle,
            max_runtime=120,
            max_attempts=3,
        )
    )
    return result
