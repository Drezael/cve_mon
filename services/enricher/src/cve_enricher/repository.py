"""Indexed input resolution and atomic fenced revisions with metadata-only events."""

import asyncio
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_enricher.contracts import RULE, Configuration, EnrichmentError, Event, Result
from cve_enricher.normalize import CVE, canonical, digest, normalize, provenance


async def emit(
    session: AsyncSession, kind: str, key: str, correlation: UUID, payload: Event
) -> None:
    await session.execute(
        text(
            "SELECT "
            "automation.emit_event(:id,:kind,1,'cve-enricher','enrichment',:ag"
            "gregate,:version,CAST(:payload AS jsonb),:key,:correlation)"
        ),
        {
            "id": uuid4(),
            "version": payload.current_version or 1,
            "kind": "cve.enrichment." + kind,
            "aggregate": digest(["identity", payload.identity])
            if payload.identity
            else str(payload.dataset_id),
            "payload": payload.model_dump_json(),
            "key": digest([kind, key]),
            "correlation": correlation,
        },
    )


async def sources(session: AsyncSession, identity: str, cfg: Configuration) -> list[dict[str, Any]]:
    ids = (
        (
            await session.execute(
                text("SELECT cve.lock_enrichment_inputs(:identity)"), {"identity": identity}
            )
        )
        .scalars()
        .all()
    )
    if len(ids) > cfg.max_source_records:
        raise EnrichmentError("source_context_limit")
    if not ids:
        return []
    size = (
        await session.execute(
            text(
                "SELECT "
                "COALESCE(sum(octet_length(v.original_json::text)),0) FROM "
                "cve.source_records r JOIN cve.source_revisions v ON "
                "v.id=r.current_revision_id WHERE r.id=ANY(:ids)"
            ),
            {"ids": ids},
        )
    ).scalar_one()
    if size > cfg.max_source_bytes:
        raise EnrichmentError("source_context_bytes")
    rows = (
        (
            await session.execute(
                text(
                    "SELECT r.id AS "
                    "record_id,r.source_id,r.external_id,r.present,v.id AS "
                    "revision_id,v.original_json,ARRAY(SELECT identifier FROM "
                    "cve.source_record_identifiers WHERE revision_id=v.id ORDER "
                    "BY identifier) AS identifiers FROM cve.source_records r "
                    "JOIN cve.source_revisions v ON v.id=r.current_revision_id "
                    "WHERE r.id=ANY(:ids) ORDER BY r.source_id,r.external_id"
                ),
                {"ids": ids},
            )
        )
        .mappings()
        .all()
    )
    return [dict(row) for row in rows]


async def kev_context(session: AsyncSession, identity: str, cfg: Configuration) -> dict[str, Any]:
    row = (
        (
            await session.execute(
                text("""
SELECT s.last_success_at,s.last_complete_run,v.id AS
revision_id,v.original_json->>'catalogVersion' AS version,
 v.original_json->>'dateReleased' AS released,v.original_json->>'count' AS entries
FROM cve.source_streams s JOIN cve.source_observations o ON o.run_id=s.last_complete_run
JOIN cve.source_records r ON r.id=o.record_id AND r.source_id='cisa_kev' AND r.external_id='catalog'
JOIN cve.source_revisions v ON v.id=o.revision_id WHERE s.source_id='cisa_kev' AND s.stream='main'
""")
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        return {"status": "unknown", "reason": "no_complete_catalog", "provenance": None}
    origin = {"source_id": "cisa_kev", "external_id": "catalog", "revision_id": row["revision_id"]}
    proof = provenance(origin, "/vulnerabilities", "complete-kev-catalog-only")
    entry = (
        (
            await session.execute(
                text("""
SELECT v.id AS revision_id,v.original_json FROM cve.source_observations o JOIN
cve.source_records r ON r.id=o.record_id
JOIN cve.source_revisions v ON v.id=o.revision_id WHERE o.run_id=:run AND
r.source_id='cisa_kev' AND r.external_id=:identity
"""),
                {"run": row["last_complete_run"], "identity": identity},
            )
        )
        .mappings()
        .first()
    )
    result: dict[str, Any] = {
        "status": "present" if entry else "absent",
        "reason": "complete_catalog",
        "catalog_revision_id": str(row["revision_id"]),
        "catalog_version": row["version"],
        "max_age_hours": cfg.kev_max_age_hours,
        "provenance": proof,
        "entry": None,
    }
    if entry:
        result["entry"] = {
            "value": entry["original_json"],
            "source_revision_id": str(entry["revision_id"]),
        }
    return result


async def enrich(
    session: AsyncSession, identity: str, job_id: UUID, correlation: UUID, cfg: Configuration
) -> Result:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:identity,16))"), {"identity": identity}
    )
    rows = await sources(session, identity, cfg)
    kev: dict[str, Any] = (
        await kev_context(session, identity, cfg)
        if CVE.fullmatch(identity)
        else {"status": "unknown", "reason": "advisory_not_cve", "provenance": None}
    )
    document = await asyncio.to_thread(normalize, identity, rows, kev)
    fingerprint = digest({"rule": RULE, "inputs": document["inputs"], "kev": kev})
    await session.execute(
        text(
            "INSERT INTO cve.enrichment_identities(identity,kind) "
            "VALUES(:identity,:kind) ON CONFLICT DO NOTHING"
        ),
        {"identity": identity, "kind": document["identity_kind"]},
    )
    previous = (
        (
            await session.execute(
                text(
                    "SELECT r.id,r.result FROM cve.enrichment_identities i LEFT JOIN "
                    "cve.enrichment_revisions r ON r.id=i.current_revision_id WHERE "
                    "i.identity=:identity FOR UPDATE OF i"
                ),
                {"identity": identity},
            )
        )
        .mappings()
        .one()
    )
    if (previous["result"] or {}).get("storage") == "v5-json":
        return Result(revision_id=previous["id"])
    inserted = (
        await session.execute(
            text(
                "INSERT INTO "
                "cve.enrichment_revisions(identity,rule_version,input_fingerprint,"
                "result,job_id) "
                "VALUES(:identity,:rule,decode(:hash,'hex'),CAST(:result AS "
                "jsonb),:job) ON "
                "CONFLICT(identity,rule_version,input_fingerprint) DO NOTHING "
                "RETURNING id"
            ),
            {
                "identity": identity,
                "rule": RULE,
                "hash": fingerprint,
                "result": canonical(document),
                "job": job_id,
            },
        )
    ).scalar_one_or_none()
    revision = (
        inserted
        or (
            await session.execute(
                text(
                    "SELECT id FROM cve.enrichment_revisions WHERE identity=:identity "
                    "AND rule_version=:rule AND input_fingerprint=decode(:hash,'hex')"
                ),
                {"identity": identity, "rule": RULE, "hash": fingerprint},
            )
        ).scalar_one()
    )
    if inserted:
        input_ids = {str(r["revision_id"]) for r in rows}
        if kev.get("catalog_revision_id"):
            input_ids.add(kev["catalog_revision_id"])
        if kev.get("entry"):
            input_ids.add(kev["entry"]["source_revision_id"])
        await session.execute(
            text(
                "INSERT INTO "
                "cve.enrichment_inputs(enrichment_revision_id,source_revision_id) "
                "SELECT :id,value::uuid FROM "
                "jsonb_array_elements_text(CAST(:inputs AS jsonb))"
            ),
            {"id": revision, "inputs": canonical(sorted(input_ids))},
        )
        assertions = []
        for category in (
            "lifecycle",
            "descriptions",
            "dates",
            "weaknesses",
            "references",
            "relations",
            "cvss",
            "affected",
            "conflicts",
            "kev",
        ):
            values = (
                document[category] if isinstance(document[category], list) else [document[category]]
            )
            for position, value in enumerate(values):
                origin = value.get("provenance") or {}
                assertions.append(
                    {
                        "category": category,
                        "position": position,
                        "value": value,
                        "origin": origin.get("source_revision_id"),
                    }
                )
        await session.execute(
            text(
                "INSERT INTO "
                "cve.enrichment_assertions(enrichment_revision_id,category,positio"
                "n,value,source_revision_id) SELECT "
                ":id,d.category,d.position,d.value,d.origin::uuid FROM "
                "jsonb_to_recordset(CAST(:items AS jsonb)) d(category "
                "text,position integer,value jsonb,origin text)"
            ),
            {"id": revision, "items": canonical(assertions)},
        )
    changed = previous["id"] != revision
    if changed:
        version = (
            await session.execute(
                text(
                    "UPDATE cve.enrichment_identities SET "
                    "current_revision_id=:revision,current_version=curren"
                    "t_version+1 WHERE identity=:identity RETURNING "
                    "current_version"
                ),
                {"identity": identity, "revision": revision},
            )
        ).scalar_one()
        old = previous["result"] or {}
        changes = [
            name
            for name in ("lifecycle", "relations", "affected", "cvss", "kev")
            if old.get(name) != document.get(name)
        ]
        payload = Event(
            identity=identity, revision_id=revision, current_version=version, changes=changes
        )
        key = identity + ":" + str(version)
        await emit(
            session,
            "created" if previous["id"] is None else "changed",
            key + ":main",
            correlation,
            payload,
        )
        kinds = {
            "relations": "aliases_changed",
            "affected": "affected_changed",
            "cvss": "cvss_changed",
            "kev": "kev_changed",
        }
        for name in changes:
            if name in kinds:
                await emit(session, kinds[name], key + ":" + name, correlation, payload)
        if (
            document["lifecycle"]["value"] == "rejected"
            and old.get("lifecycle") != document["lifecycle"]
        ):
            await emit(session, "rejected", key + ":rejected", correlation, payload)
    return Result(revision_id=revision, changed=changed)
