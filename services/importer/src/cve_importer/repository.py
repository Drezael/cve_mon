"""Set-oriented source persistence; no summary fusion or inventory/administrative writes."""

import hashlib
from collections import Counter
from collections.abc import Sequence
from typing import Any
from uuid import UUID, uuid4

from cve_common.events.registry import EventDefinition, EventRegistry
from cve_common.jobs.contracts import Payload
from sqlalchemy import text
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncSession

from cve_importer.adapters import Page
from cve_importer.contracts import Configuration, ImportFailure, Source
from cve_importer.validation import CVE, canonical


class Event(Payload):
    run_id: UUID
    source_id: Source
    record_id: UUID | None = None
    revision_id: UUID | None = None
    external_id: str | None = None
    code: str | None = None


EVENTS = EventRegistry()
for _kind in ("new", "changed", "withdrawn", "removed", "completed", "partial", "failed"):
    EVENTS.register(EventDefinition("cve.source." + _kind, 1, "cve-importer", Event))


async def events(
    session: AsyncSession, run: dict[str, Any], items: list[tuple[str, Event]]
) -> None:
    rows = []
    for kind, payload in items:
        value = payload.model_dump(mode="json")
        EVENTS.validate("cve.source." + kind, 1, "cve-importer", value)
        key = hashlib.sha256(
            (str(run["id"]) + kind + str(payload.record_id) + str(payload.revision_id)).encode()
        ).hexdigest()
        rows.append(
            {
                "event_id": str(uuid4()),
                "kind": "cve.source." + kind,
                "aggregate": str(payload.record_id or run["id"]),
                "key": key,
                "payload": value,
            }
        )
    if rows:
        await session.execute(
            text(
                "SELECT "
                "automation.emit_event(d.event_id::uuid,d.kind,1,'cve-importer','s"
                "ource_record',d.aggregate,1,d.payload,d.key,:correlation) FROM "
                "jsonb_to_recordset(CAST(:rows AS jsonb)) AS d(event_id text,kind "
                "text,aggregate text,key text,payload jsonb)"
            ),
            {"rows": canonical(rows), "correlation": run["correlation_id"]},
        )


async def artifacts(session: AsyncSession, run: dict[str, Any], page: Page) -> dict[str, UUID]:
    data: dict[str, dict[str, Any]] = {
        page.artifact.location: {
            "location": page.artifact.location,
            "sha": page.artifact.sha256.hex(),
            "bytes": page.artifact.size,
            "metadata": page.artifact.metadata(),
            "milliseconds": page.artifact.milliseconds,
        }
    }
    for row in page.records:
        if "artifact_location" in row:
            data[row["artifact_location"]] = {
                "location": row["artifact_location"],
                "sha": row["artifact_sha256"],
                "bytes": row["artifact_size"],
                "metadata": {},
                "milliseconds": row.get("artifact_milliseconds", 0),
            }
    params = {"source": run["source_id"], "run": run["id"], "data": canonical(list(data.values()))}
    inserted = (
        (
            await session.execute(
                text(
                    "INSERT INTO "
                    "cve.source_artifacts(source_id,run_id,location,sha256,bytes,metad"
                    "ata) SELECT "
                    ":source,:run,d.location,decode(d.sha,'hex'),d.bytes,d.metadata "
                    "FROM jsonb_to_recordset(CAST(:data AS jsonb)) AS d(location "
                    "text,sha text,bytes bigint,metadata jsonb) ON "
                    "CONFLICT(run_id,location,sha256) DO NOTHING RETURNING "
                    "location,bytes"
                ),
                params,
            )
        )
        .mappings()
        .all()
    )
    await session.execute(
        text(
            "UPDATE cve.import_runs SET "
            "download_bytes=download_bytes+:bytes,download_ms=download_ms+:mil"
            "liseconds WHERE id=:id"
        ),
        {
            "bytes": sum(r["bytes"] for r in inserted),
            "milliseconds": sum(data[r["location"]]["milliseconds"] for r in inserted),
            "id": run["id"],
        },
    )
    rows = (
        (
            await session.execute(
                text(
                    "SELECT id,location FROM cve.source_artifacts WHERE run_id=:run "
                    "AND location=ANY(:locations)"
                ),
                {"run": run["id"], "locations": list(data)},
            )
        )
        .mappings()
        .all()
    )
    return {row["location"]: row["id"] for row in rows}


async def persist(session: AsyncSession, run: dict[str, Any], page: Page) -> dict[str, int]:
    cfg = Configuration.model_validate(run["context"].get("configuration", {}))
    native = run["source_id"] == "cve_list" and cfg.cve_list_transport == "git"
    artifact_ids = await artifacts(session, run, page)
    artifact_id = artifact_ids[page.artifact.location]
    notifications: list[tuple[str, Event]] = []
    incoming: dict[str, dict[str, Any]] = {}
    for item in page.records:
        key = item["external_id"]
        if key in incoming and incoming[key]["original_json"] != item["original_json"]:
            raise ImportFailure("duplicate_source_identity")
        incoming[key] = {
            **item,
            "git_commit": page.progress.get("git", {}).get("head") if native else None,
            "git_path": item["position"] if native else None,
            "artifact_id": str(artifact_ids[item.get("artifact_location", page.artifact.location)]),
        }
    values = list(incoming.values())
    params = {
        "source": run["source_id"],
        "run": run["id"],
        "artifact": artifact_id,
        "values": canonical(values),
    }
    stats = Counter({"read": len(page.records) + len(page.errors)})
    if values:
        await session.execute(
            text(
                "INSERT INTO "
                "cve.source_records(source_id,external_id,last_seen_run) SELECT "
                ":source,d.external_id,:run FROM jsonb_to_recordset(CAST(:values "
                "AS jsonb)) AS d(external_id text) ON "
                "CONFLICT(source_id,external_id) DO NOTHING"
            ),
            params,
        )
        existing = (
            (
                await session.execute(
                    text(
                        "SELECT r.id,r.external_id,r.current_revision_id,v.modified_at "
                        "FROM cve.source_records r LEFT JOIN cve.source_revisions v ON "
                        "v.id=r.current_revision_id WHERE r.source_id=:source AND "
                        "r.external_id=ANY(:ids) ORDER BY r.external_id FOR UPDATE OF r"
                    ),
                    {"source": run["source_id"], "ids": list(incoming)},
                )
            )
            .mappings()
            .all()
        )
        old = {row["external_id"]: row for row in existing}
        await session.execute(
            text(
                "INSERT INTO "
                "cve.source_revisions(record_id,source_id,original_json,original_r"
                "ecord_sha256,source_version,source_status,status,published_at,mod"
                "ified_at,run_id,artifact_id,git_commit,git_path,git_blob_oid) SELECT "
                "r.id,:source,d.original_json,decode(d.original_record_sha256,'hex"
                "'),d.source_version,d.source_status,d.status,d.published_at::time"
                "stamptz,d.modified_at::timestamptz,:run,d.artifact_id::uuid,"
                "d.git_commit,d.git_path,d.git_blob_oid FROM "
                "jsonb_to_recordset(CAST(:values AS jsonb)) AS d(external_id "
                "text,original_json jsonb,original_record_sha256 "
                "text,source_version text,source_status text,status "
                "text,published_at text,modified_at text,artifact_id text,"
                "git_commit text,git_path text,git_blob_oid text) JOIN "
                "cve.source_records r ON r.source_id=:source AND "
                "r.external_id=d.external_id ON "
                "CONFLICT(record_id,content_sha256) DO NOTHING"
            ),
            params,
        )
        versions = (
            (
                await session.execute(
                    text(
                        "SELECT v.id AS "
                        "revision_id,v.record_id,r.external_id,v.modified_at FROM "
                        "jsonb_to_recordset(CAST(:values AS jsonb)) AS d(external_id "
                        "text,original_json jsonb) JOIN cve.source_records r ON "
                        "r.source_id=:source AND r.external_id=d.external_id JOIN "
                        "cve.source_revisions v ON v.record_id=r.id AND "
                        "v.content_sha256=sha256(convert_to(d.original_json::text,'UTF8'))"
                    ),
                    params,
                )
            )
            .mappings()
            .all()
        )
        updates = []
        observations = []
        identifiers = []
        for version in versions:
            item = incoming[version["external_id"]]
            previous = old[version["external_id"]]
            stale = (
                run["mode"] == "incremental"
                and run["source_id"] in {"nvd", "osv", "ubuntu"}
                and previous["modified_at"] is not None
                and version["modified_at"] is not None
                and version["modified_at"] < previous["modified_at"]
            )
            disposition = (
                "stale"
                if stale
                else "new"
                if previous["current_revision_id"] is None
                else "unchanged"
                if previous["current_revision_id"] == version["revision_id"]
                else "changed"
            )
            if not stale:
                updates.append(
                    {
                        "record_id": str(version["record_id"]),
                        "revision_id": str(version["revision_id"]),
                    }
                )
            observations.append(
                {
                    "record_id": str(version["record_id"]),
                    "revision_id": str(version["revision_id"]),
                    "position": item["position"],
                    "disposition": disposition,
                    "artifact_id": item["artifact_id"],
                }
            )
            for alias in item["identifiers"]:
                identifiers.append(
                    {
                        "revision_id": str(version["revision_id"]),
                        "identifier": alias,
                        "kind": "cve" if CVE.fullmatch(alias) else "advisory",
                    }
                )
            if disposition in {"new", "changed"}:
                kind = "withdrawn" if item["status"] in {"withdrawn", "rejected"} else disposition
                notifications.append(
                    (
                        kind,
                        Event(
                            run_id=run["id"],
                            source_id=run["source_id"],
                            record_id=version["record_id"],
                            revision_id=version["revision_id"],
                            external_id=item["external_id"],
                        ),
                    )
                )
        params["observations"] = canonical(observations)
        inserted = (
            (
                await session.execute(
                    text(
                        "INSERT INTO "
                        "cve.source_observations(run_id,record_id,revision_id,artifact_id,"
                        "position,disposition) SELECT "
                        ":run,d.record_id::uuid,d.revision_id::uuid,d.artifact_id::uuid,d."
                        "position,d.disposition FROM "
                        "jsonb_to_recordset(CAST(:observations AS jsonb)) AS d(record_id "
                        "text,revision_id text,position text,disposition text,artifact_id "
                        "text) ON CONFLICT DO NOTHING RETURNING disposition"
                    ),
                    params,
                )
            )
            .scalars()
            .all()
        )
        stats.update(inserted)
        if updates:
            await session.execute(
                text(
                    "UPDATE cve.source_records r SET "
                    "current_revision_id=d.revision_id::uuid,last_seen_run=:run,last_s"
                    "een_at=clock_timestamp(),present=true FROM "
                    "jsonb_to_recordset(CAST(:updates AS jsonb)) AS d(record_id "
                    "text,revision_id text) WHERE r.id=d.record_id::uuid AND "
                    "r.source_id=:source"
                ),
                {"updates": canonical(updates), **params},
            )
        if identifiers and not native:
            params["identifiers"] = canonical(identifiers)
            await session.execute(
                text(
                    "INSERT INTO cve.source_identifiers(identifier,kind) SELECT "
                    "DISTINCT d.identifier,d.kind FROM "
                    "jsonb_to_recordset(CAST(:identifiers AS jsonb)) AS d(identifier "
                    "text,kind text) ON CONFLICT DO NOTHING"
                ),
                params,
            )
            await session.execute(
                text(
                    "INSERT INTO "
                    "cve.source_record_identifiers(revision_id,identifier) SELECT "
                    "DISTINCT d.revision_id::uuid,d.identifier FROM "
                    "jsonb_to_recordset(CAST(:identifiers AS jsonb)) AS d(revision_id "
                    "text,identifier text) ON CONFLICT DO NOTHING"
                ),
                params,
            )
        if not native:
            await events(session, run, notifications)
    removed: Sequence[RowMapping] = []
    if page.removed:
        removed = (
            (
                await session.execute(
                    text("""
UPDATE cve.source_records SET present=false,last_seen_run=:run,last_seen_at=clock_timestamp()
WHERE source_id=:source AND external_id=ANY(:ids) AND present
RETURNING id,external_id,current_revision_id
"""),
                    {"run": run["id"], "source": run["source_id"], "ids": page.removed},
                )
            )
            .mappings()
            .all()
        )
        await session.execute(
            text("""
INSERT INTO cve.source_presence(run_id,record_id,present)
SELECT :run,value::uuid,false FROM jsonb_array_elements_text(CAST(:ids AS jsonb))
ON CONFLICT DO NOTHING
"""),
            {"run": run["id"], "ids": canonical([str(r["id"]) for r in removed])},
        )
        if not native:
            await events(
                session,
                run,
                [
                    (
                        "removed",
                        Event(
                            run_id=run["id"],
                            source_id=run["source_id"],
                            record_id=r["id"],
                            revision_id=r["current_revision_id"],
                            external_id=r["external_id"],
                        ),
                    )
                    for r in removed
                ],
            )
        stats["read"] += len(page.removed)
        stats["changed"] += len(removed)
    if native:
        identities = sorted(set(incoming) | {r["external_id"] for r in removed})
        await publish_native(session, run, identities, cfg)
    if page.errors:
        errors = canonical(page.errors)
        inserted = (
            await session.execute(
                text(
                    "INSERT INTO cve.import_errors(run_id,position,code) SELECT "
                    ":run,d.position,d.code FROM jsonb_to_recordset(CAST(:errors AS "
                    "jsonb)) AS d(position text,code text) ON CONFLICT DO NOTHING "
                    "RETURNING code"
                ),
                {"run": run["id"], "errors": errors},
            )
        ).all()
        stats["error"] = len(inserted)
    await session.execute(
        text(
            "UPDATE cve.import_runs SET "
            "read_count=read_count+:read,new_count=new_count+:new,changed_coun"
            "t=changed_count+:changed,unchanged_count=unchanged_count+:unchang"
            "ed,stale_count=stale_count+:stale,error_count=error_count+:error,"
            "parse_ms=parse_ms+:parse WHERE id=:run"
        ),
        {
            **{
                key: stats[key] for key in ("read", "new", "changed", "unchanged", "stale", "error")
            },
            "parse": page.parse_ms,
            "run": run["id"],
        },
    )
    return dict(stats)


async def publish_native(
    session: AsyncSession, run: dict[str, Any], identities: list[str], cfg: Configuration
) -> None:
    """Publish tiny revision handles and one durable index job per package atomically."""
    published = []
    if identities:
        published = list(
            (
                await session.execute(
                    text("SELECT * FROM cve.publish_v5(:run,:ids)"),
                    {"run": run["id"], "ids": identities},
                )
            ).mappings()
        )
    published.sort(key=lambda r: r["identity"])
    batches = [
        {
            "payload": {
                "revisions": [
                    str(r["revision_id"]) for r in published[i : i + cfg.enrichment_batch_size]
                ]
            },
            "key": str(run["id"])
            + ":v5:"
            + hashlib.sha256(
                canonical(
                    [
                        [str(r["revision_id"]), r["current_version"]]
                        for r in published[i : i + cfg.enrichment_batch_size]
                    ]
                ).encode()
            ).hexdigest(),
        }
        for i in range(0, len(published), cfg.enrichment_batch_size)
    ]
    if batches:
        await session.execute(
            text("""
SELECT automation.enqueue_job('matching.index_v5_batch',1,d.payload,d.key,:correlation,
0,NULL,NULL,3,'v5-json-batch',false) FROM jsonb_to_recordset(CAST(:rows AS jsonb))
d(payload jsonb,key text)
"""),
            {"rows": canonical(batches), "correlation": run["correlation_id"]},
        )


async def finish(
    session: AsyncSession, run: dict[str, Any], page: Page, minimum_fraction: float
) -> str:
    errors = int(
        (
            await session.execute(
                text("SELECT error_count FROM cve.import_runs WHERE id=:id"), {"id": run["id"]}
            )
        ).scalar_one()
    )
    status = "partial" if errors else "completed"
    cfg = Configuration.model_validate(run["context"].get("configuration", {}))
    if (
        status == "completed"
        and run["source_id"] == "cve_list"
        and cfg.cve_list_transport == "git"
        and page.progress.get("git", {}).get("base") is None
    ):
        after = ""
        while True:
            missing = list(
                (
                    await session.execute(
                        text("""
WITH missing AS (
 SELECT id FROM cve.source_records WHERE source_id='cve_list' AND present
 AND last_seen_run IS DISTINCT FROM :run AND external_id>:after
 ORDER BY external_id LIMIT 1000 FOR UPDATE
)
UPDATE cve.source_records r SET present=false,last_seen_run=:run,last_seen_at=clock_timestamp()
FROM missing m WHERE r.id=m.id RETURNING r.id,r.external_id
"""),
                        {"run": run["id"], "after": after},
                    )
                ).mappings()
            )
            if not missing:
                break
            identities = sorted(r["external_id"] for r in missing)
            await session.execute(
                text("""
INSERT INTO cve.source_presence(run_id,record_id,present)
SELECT :run,value::uuid,false FROM jsonb_array_elements_text(CAST(:ids AS jsonb))
ON CONFLICT DO NOTHING
"""),
                {"run": run["id"], "ids": canonical([str(r["id"]) for r in missing])},
            )
            await publish_native(session, run, identities, cfg)
            after = identities[-1]
    if status == "completed" and run["source_id"] == "cisa_kev":
        previous = int(
            (
                await session.execute(
                    text(
                        "SELECT count(*) FROM cve.source_records WHERE "
                        "source_id='cisa_kev' AND external_id<>'catalog' AND present"
                    )
                )
            ).scalar_one()
        )
        count = page.cursors["main"]["count"]
        if previous and count < previous * minimum_fraction:
            raise ImportFailure("kev_catalog_regression")
        removed = (
            (
                await session.execute(
                    text(
                        "UPDATE cve.source_records SET present=false WHERE "
                        "source_id='cisa_kev' AND external_id<>'catalog' AND present AND "
                        "last_seen_run<>:run RETURNING id,external_id,current_revision_id"
                    ),
                    {"run": run["id"]},
                )
            )
            .mappings()
            .all()
        )
        if removed:
            await session.execute(
                text(
                    "INSERT INTO cve.source_presence(run_id,record_id,present) SELECT "
                    ":run,d.id::uuid,false FROM jsonb_to_recordset(CAST(:rows AS "
                    "jsonb)) AS d(id text) ON CONFLICT DO NOTHING"
                ),
                {"run": run["id"], "rows": canonical([{"id": str(r["id"])} for r in removed])},
            )
            await events(
                session,
                run,
                [
                    (
                        "removed",
                        Event(
                            run_id=run["id"],
                            source_id="cisa_kev",
                            record_id=r["id"],
                            revision_id=r["current_revision_id"],
                            external_id=r["external_id"],
                        ),
                    )
                    for r in removed
                ],
            )
    if status == "completed":
        for stream, cursor in page.cursors.items():
            await session.execute(
                text(
                    "INSERT INTO "
                    "cve.source_streams(source_id,stream,cursor,last_complete_run,last"
                    "_success_at) VALUES(:source,:stream,CAST(:cursor AS "
                    "jsonb),:run,clock_timestamp()) ON CONFLICT(source_id,stream) DO "
                    "UPDATE SET "
                    "cursor=excluded.cursor,last_complete_run=excluded.last_complete_r"
                    "un,last_success_at=excluded.last_success_at"
                ),
                {
                    "source": run["source_id"],
                    "stream": stream,
                    "cursor": canonical(cursor),
                    "run": run["id"],
                },
            )
        await session.execute(
            text(
                "INSERT INTO "
                "system.source_sync_state(source_id,cursor,last_success_at) "
                "VALUES(:source,CAST(:cursor AS jsonb),clock_timestamp()) ON "
                "CONFLICT(source_id) DO UPDATE SET "
                "cursor=system.source_sync_state.cursor||excluded.cursor,last_succ"
                "ess_at=excluded.last_success_at,last_error_code=NULL,updated_at=c"
                "lock_timestamp()"
            ),
            {"source": run["source_id"], "cursor": canonical({"importer_v1": page.cursors})},
        )
    if status == "partial":
        await session.execute(
            text(
                "INSERT INTO system.source_sync_state(source_id,last_error_code) "
                "VALUES(:source,'partial') ON CONFLICT(source_id) DO UPDATE SET "
                "last_error_code='partial',updated_at=clock_timestamp()"
            ),
            {"source": run["source_id"]},
        )
    await session.execute(
        text(
            "UPDATE cve.import_runs SET status=:status,finished_at=clock_timestamp() WHERE id=:id"
        ),
        {"status": status, "id": run["id"]},
    )
    await session.execute(
        text(
            "UPDATE cve.source_leases SET active_run=NULL WHERE "
            "source_id=:source AND active_run=:id"
        ),
        {"source": run["source_id"], "id": run["id"]},
    )
    await events(session, run, [(status, Event(run_id=run["id"], source_id=run["source_id"]))])
    await session.execute(
        text(
            "INSERT INTO "
            "security.audit_log(action,object_type,object_id,request_id,outcom"
            "e,metadata) VALUES(:action,'cve_import',:id,:cid,:outcome,'{}')"
        ),
        {
            "action": "cve.source." + status,
            "id": str(run["id"]),
            "cid": run["correlation_id"],
            "outcome": "success" if status == "completed" else "denied",
        },
    )
    return status
