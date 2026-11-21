"""Parallel preparation and set-oriented publication of immutable enrichment revisions."""

import asyncio
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_common.jobs.errors import ErrorCode, JobError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_enricher.contracts import RULE, Configuration, EnrichmentError, Event, Result
from cve_enricher.normalize import CVE, canonical, digest, normalize
from cve_enricher.repository import kev_context, sources


@dataclass(frozen=True)
class Prepared:
    identity: str
    document: dict[str, Any]
    refs: list[dict[str, Any]]
    kev: dict[str, Any]
    catalog: str | None
    job: UUID
    correlation: UUID


def references(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        [
            {"id": str(r["record_id"]), "revision": str(r["revision_id"]), "present": r["present"]}
            for r in rows
        ],
        key=lambda r: r["id"],
    )


async def prepare(
    database: Database, identity: str, job: UUID, correlation: UUID, cfg: Configuration
) -> Prepared:
    # Release read locks before CPU work or queue backpressure. Immutable revisions remain readable.
    async with transaction(database) as session:
        rows = await sources(session, identity, cfg)
        kev = (
            await kev_context(session, identity, cfg)
            if CVE.fullmatch(identity)
            else {"status": "unknown", "reason": "advisory_not_cve", "provenance": None}
        )
        catalog = (
            await session.execute(
                text(
                    "SELECT last_complete_run FROM cve.source_streams "
                    "WHERE source_id='cisa_kev' AND stream='main'"
                )
            )
        ).scalar_one_or_none()
    document = await asyncio.to_thread(normalize, identity, rows, kev)
    return Prepared(
        identity,
        document,
        references(rows),
        kev,
        str(catalog) if catalog else None,
        job,
        correlation,
    )


async def publish(session: AsyncSession, values: list[Prepared]) -> list[Result]:
    if not values:
        return []
    items: dict[str, Prepared] = {}
    for value in values:
        items.setdefault(value.identity, value)
    identities = sorted(items)
    await session.execute(
        text(
            "SELECT pg_advisory_xact_lock(hashtextextended(identity,16)) "
            "FROM unnest(CAST(:ids AS text[])) identity ORDER BY identity"
        ),
        {"ids": identities},
    )
    # Lock first, then read in a new READ COMMITTED snapshot after any lock wait.
    locked = (
        (
            await session.execute(
                text("""
SELECT i.identity, locked.id::text AS id
FROM unnest(CAST(:ids AS text[])) i(identity)
LEFT JOIN LATERAL cve.lock_enrichment_inputs(i.identity) locked(id) ON true
ORDER BY i.identity
"""),
                {"ids": identities},
            )
        )
        .mappings()
        .all()
    )
    current = (
        (
            await session.execute(
                text("""
SELECT d.identity, COALESCE(jsonb_agg(jsonb_build_object(
 'id',r.id::text,'revision',r.current_revision_id::text,'present',r.present)
 ORDER BY r.id::text) FILTER (WHERE r.id IS NOT NULL),'[]'::jsonb) AS refs
FROM jsonb_to_recordset(CAST(:rows AS jsonb)) d(identity text,id uuid)
LEFT JOIN cve.source_records r ON r.id=d.id GROUP BY d.identity
"""),
                {"rows": canonical([dict(r) for r in locked])},
            )
        )
        .mappings()
        .all()
    )
    catalog = (
        await session.execute(
            text(
                "SELECT last_complete_run FROM cve.source_streams "
                "WHERE source_id='cisa_kev' AND stream='main'"
            )
        )
    ).scalar_one_or_none()
    refs = {r["identity"]: r["refs"] for r in current}
    for value in values:
        if refs[value.identity] != value.refs or value.catalog != (
            str(catalog) if catalog else None
        ):
            raise JobError(ErrorCode.TEMPORARY)
    rows = [
        {
            "identity": v.identity,
            "kind": v.document["identity_kind"],
            "revision": str(uuid4()),
            "fingerprint": digest({"rule": RULE, "inputs": v.document["inputs"], "kev": v.kev}),
            "result": v.document,
            "job": str(v.job),
        }
        for v in items.values()
    ]
    params = {"rows": canonical(rows), "rule": RULE, "ids": identities}
    await session.execute(
        text("""
INSERT INTO cve.enrichment_identities(identity,kind)
SELECT d.identity,d.kind FROM jsonb_to_recordset(CAST(:rows AS jsonb)) d(identity text,kind text)
ORDER BY d.identity ON CONFLICT DO NOTHING
"""),
        params,
    )
    previous = {
        r["identity"]: r
        for r in (
            await session.execute(
                text("""
SELECT i.identity,r.id,r.result,r.input_fingerprint FROM cve.enrichment_identities i
LEFT JOIN cve.enrichment_revisions r ON r.id=i.current_revision_id
WHERE i.identity=ANY(:ids) ORDER BY i.identity FOR UPDATE OF i
"""),
                params,
            )
        ).mappings()
    }
    # Native documents are authoritative; explicit legacy backfills must not replace them.
    native = {
        identity: row["id"]
        for identity, row in previous.items()
        if (row["result"] or {}).get("storage") == "v5-json"
    }
    rows = [row for row in rows if row["identity"] not in native]
    params["rows"] = canonical(rows)
    if all(
        previous[r["identity"]]["id"] is not None
        and bytes(previous[r["identity"]]["input_fingerprint"]).hex() == r["fingerprint"]
        for r in rows
    ):
        # Reconcile queues often contain already-current inputs. No revision/outbox write is needed.
        return [Result(revision_id=previous[v.identity]["id"]) for v in values]
    inserted = {
        r["identity"]: r["id"]
        for r in (
            await session.execute(
                text("""
INSERT INTO cve.enrichment_revisions(id,identity,rule_version,input_fingerprint,result,job_id)
SELECT d.revision,d.identity,:rule,decode(d.fingerprint,'hex'),d.result,d.job
FROM jsonb_to_recordset(CAST(:rows AS jsonb))
d(revision uuid,identity text,fingerprint text,result jsonb,job uuid)
ON CONFLICT(identity,rule_version,input_fingerprint) DO NOTHING RETURNING identity,id
"""),
                params,
            )
        ).mappings()
    }
    revisions = {
        r["identity"]: r["id"]
        for r in (
            await session.execute(
                text("""
SELECT r.identity,r.id FROM jsonb_to_recordset(CAST(:rows AS jsonb))
d(identity text,fingerprint text) JOIN cve.enrichment_revisions r
ON r.identity=d.identity AND r.rule_version=:rule 
AND r.input_fingerprint=decode(d.fingerprint,'hex')
"""),
                params,
            )
        ).mappings()
    }
    inputs: list[dict[str, Any]] = []
    assertions: list[dict[str, Any]] = []
    for identity, revision in inserted.items():
        value = items[identity]
        input_ids = {r["revision"] for r in value.refs}
        if value.kev.get("catalog_revision_id"):
            input_ids.add(value.kev["catalog_revision_id"])
        if value.kev.get("entry"):
            input_ids.add(value.kev["entry"]["source_revision_id"])
        inputs.extend({"revision": str(revision), "source": source} for source in sorted(input_ids))
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
            field = value.document[category]
            for position, assertion in enumerate(field if isinstance(field, list) else [field]):
                assertions.append(
                    {
                        "revision": str(revision),
                        "category": category,
                        "position": position,
                        "value": assertion,
                        "origin": (assertion.get("provenance") or {}).get("source_revision_id"),
                    }
                )
    await session.execute(
        text("""
INSERT INTO cve.enrichment_inputs(enrichment_revision_id,source_revision_id)
SELECT d.revision,d.source FROM jsonb_to_recordset(CAST(:rows AS jsonb))
d(revision uuid,source uuid)
"""),
        {"rows": canonical(inputs)},
    )
    await session.execute(
        text("""
INSERT INTO cve.enrichment_assertions
(enrichment_revision_id,category,position,value,source_revision_id)
SELECT d.revision,d.category,d.position,d.value,d.origin
FROM jsonb_to_recordset(CAST(:rows AS jsonb))
d(revision uuid,category text,position integer,value jsonb,origin uuid)
"""),
        {"rows": canonical(assertions)},
    )
    changed = [
        {"identity": identity, "revision": str(revision)}
        for identity, revision in revisions.items()
        if previous[identity]["id"] != revision
    ]
    versions = {
        r["identity"]: r["current_version"]
        for r in (
            await session.execute(
                text("""
UPDATE cve.enrichment_identities i SET current_revision_id=d.revision,
current_version=i.current_version+1 FROM jsonb_to_recordset(CAST(:rows AS jsonb))
d(identity text,revision uuid) WHERE i.identity=d.identity RETURNING i.identity,i.current_version
"""),
                {"rows": canonical(changed)},
            )
        ).mappings()
    }
    events = []
    for identity, version in versions.items():
        value = items[identity]
        old = previous[identity]["result"] or {}
        changes = [
            name
            for name in ("lifecycle", "relations", "affected", "cvss", "kev")
            if old.get(name) != value.document.get(name)
        ]
        payload = Event(
            identity=identity,
            revision_id=revisions[identity],
            current_version=version,
            changes=changes,
        )
        kinds = [("created" if previous[identity]["id"] is None else "changed", "main")]
        mapping = {
            "relations": "aliases_changed",
            "affected": "affected_changed",
            "cvss": "cvss_changed",
            "kev": "kev_changed",
        }
        kinds.extend((mapping[name], name) for name in changes if name in mapping)
        if value.document["lifecycle"]["value"] == "rejected" and "lifecycle" in changes:
            kinds.append(("rejected", "rejected"))
        for kind, suffix in kinds:
            events.append(
                {
                    "id": str(uuid4()),
                    "kind": "cve.enrichment." + kind,
                    "aggregate": digest(["identity", identity]),
                    "version": version,
                    "payload": payload.model_dump(mode="json"),
                    "key": digest([kind, f"{identity}:{version}:{suffix}"]),
                    "correlation": str(value.correlation),
                }
            )
    await session.execute(
        text("""
SELECT automation.emit_event(d.id,d.kind,1,'cve-enricher','enrichment',d.aggregate,
d.version,d.payload,d.key,d.correlation) FROM jsonb_to_recordset(CAST(:rows AS jsonb))
d(id uuid,kind text,aggregate text,version bigint,payload jsonb,key text,correlation uuid)
"""),
        {"rows": canonical(events)},
    )
    revisions.update(native)
    results = []
    for value in values:
        results.append(
            Result(revision_id=revisions[value.identity], changed=value.identity in versions)
        )
        versions.pop(value.identity, None)
    return results


def prepared_size(values: list[Prepared]) -> int:
    size = sum(
        len(canonical(v.document).encode())
        + len(canonical(v.kev).encode())
        + len(canonical(v.refs).encode())
        for v in values
    )
    if size > 64 * 1024 * 1024:
        raise EnrichmentError("prepared_context_bytes")
    return size


async def prepare_many(
    database: Database, identities: list[str], job: UUID, correlation: UUID, cfg: Configuration
) -> list[Prepared]:
    """Resolve a bounded package with constant read roundtrips before parallel job CPU work."""
    from cve_enricher.normalize import provenance

    identities = sorted(set(identities))
    if not 1 <= len(identities) <= 128:
        raise EnrichmentError("identity_batch_limit")
    async with transaction(database) as session:
        pairs = (
            (
                await session.execute(
                    text("""
SELECT i.identity,locked.id FROM unnest(CAST(:ids AS text[])) i(identity)
LEFT JOIN LATERAL cve.lock_enrichment_inputs(i.identity) locked(id) ON true ORDER BY i.identity
"""),
                    {"ids": identities},
                )
            )
            .mappings()
            .all()
        )
        mapping: dict[str, list[UUID]] = {identity: [] for identity in identities}
        for pair in pairs:
            if pair["id"] is not None:
                mapping[pair["identity"]].append(pair["id"])
        if any(len(ids) > cfg.max_source_records for ids in mapping.values()):
            raise EnrichmentError("source_context_limit")
        ids = sorted({record_id for refs in mapping.values() for record_id in refs})
        size = (
            await session.execute(
                text("""
SELECT COALESCE(sum(octet_length(v.original_json::text)),0) FROM cve.source_records r
JOIN cve.source_revisions v ON v.id=r.current_revision_id WHERE r.id=ANY(:ids)
"""),
                {"ids": ids},
            )
        ).scalar_one()
        if size > cfg.max_source_bytes:
            raise EnrichmentError("source_context_bytes")
        rows = (
            (
                await session.execute(
                    text("""
SELECT r.id AS record_id,r.source_id,r.external_id,r.present,v.id AS revision_id,v.original_json,
ARRAY(SELECT identifier FROM cve.source_record_identifiers WHERE revision_id=v.id
ORDER BY identifier) AS identifiers FROM cve.source_records r
JOIN cve.source_revisions v ON v.id=r.current_revision_id WHERE r.id=ANY(:ids)
ORDER BY r.source_id,r.external_id
"""),
                    {"ids": ids},
                )
            )
            .mappings()
            .all()
        )
        catalog = (
            (
                await session.execute(
                    text("""
SELECT s.last_complete_run,c.* FROM cve.source_streams s LEFT JOIN LATERAL (
 SELECT v.id AS revision_id,v.original_json->>'catalogVersion' AS version
 FROM cve.source_observations o JOIN cve.source_records r ON r.id=o.record_id
 JOIN cve.source_revisions v ON v.id=o.revision_id
 WHERE o.run_id=s.last_complete_run AND r.source_id='cisa_kev' AND r.external_id='catalog'
) c ON true WHERE s.source_id='cisa_kev' AND s.stream='main'
""")
                )
            )
            .mappings()
            .first()
        )
        kev_values: dict[str, dict[str, Any]] = {}
        entries = {}
        if catalog and catalog["revision_id"]:
            entries = {
                r["external_id"]: r
                for r in (
                    await session.execute(
                        text("""
SELECT r.external_id,v.id AS revision_id,v.original_json FROM cve.source_observations o
JOIN cve.source_records r ON r.id=o.record_id JOIN cve.source_revisions v ON v.id=o.revision_id
WHERE o.run_id=:run AND r.source_id='cisa_kev' AND r.external_id=ANY(:ids)
"""),
                        {"run": catalog["last_complete_run"], "ids": identities},
                    )
                ).mappings()
            }
        for identity in identities:
            kev: dict[str, Any] = {
                "status": "unknown",
                "reason": "no_complete_catalog",
                "provenance": None,
            }
            if not CVE.fullmatch(identity):
                kev["reason"] = "advisory_not_cve"
            elif catalog and catalog["revision_id"]:
                entry = entries.get(identity)
                origin = {
                    "source_id": "cisa_kev",
                    "external_id": "catalog",
                    "revision_id": catalog["revision_id"],
                }
                kev = {
                    "status": "present" if entry else "absent",
                    "reason": "complete_catalog",
                    "catalog_revision_id": str(catalog["revision_id"]),
                    "catalog_version": catalog["version"],
                    "max_age_hours": cfg.kev_max_age_hours,
                    "provenance": provenance(
                        origin, "/vulnerabilities", "complete-kev-catalog-only"
                    ),
                    "entry": {
                        "value": entry["original_json"],
                        "source_revision_id": str(entry["revision_id"]),
                    }
                    if entry
                    else None,
                }
            kev_values[identity] = kev
        token = (
            str(catalog["last_complete_run"]) if catalog and catalog["last_complete_run"] else None
        )
    by_id = {r["record_id"]: dict(r) for r in rows}

    def build() -> list[Prepared]:
        results = []
        for identity in identities:
            selected = sorted(
                [by_id[key] for key in mapping[identity] if key in by_id],
                key=lambda row: (row["source_id"], row["external_id"]),
            )
            kev = kev_values[identity]
            results.append(
                Prepared(
                    identity,
                    normalize(identity, selected, kev),
                    references(selected),
                    kev,
                    token,
                    job,
                    correlation,
                )
            )
        prepared_size(results)
        return results

    return await asyncio.to_thread(build)
