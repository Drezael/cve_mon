"""Indexed bidirectional candidate selection and fenced immutable persistence."""

import asyncio
from typing import Any
from uuid import UUID, uuid4

from cve_common.database.engine import Database
from cve_common.jobs.errors import ErrorCode, JobError
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import JobDefinition, Registry
from cve_common.v5 import revisions as load_revisions
from cve_common.workflows import centrally_controlled
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_matcher.container_software import software_components
from cve_matcher.contracts import RULE, Request, Result
from cve_matcher.engine import (
    EvaluationLimit,
    canonical,
    component_keys,
    components,
    digest,
    evaluate,
    source_keys,
)

PAGE = 100
MAX_BYTES = 33554432
MAX_COMPONENTS = 100000


async def rows(s: AsyncSession, sql: str, **params: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in (await s.execute(text(sql), params)).mappings()]


async def enqueue(
    s: AsyncSession,
    kind: str,
    payload: Request,
    key: str,
    correlation: UUID,
    *,
    technical: bool | None = None,
) -> None:
    await s.execute(
        text(
            "SELECT automation.enqueue_job(:kind,1,CAST(:payload AS jsonb),:ke"
            "y,:correlation,0,NULL,NULL,3,:scope,false)"
        ),
        {
            "kind": "matching." + kind,
            "payload": payload.model_dump_json(),
            "key": digest(key),
            "correlation": correlation,
            "scope": "matching-internal"
            if (technical if technical is not None else kind != "evaluate_v5_batch")
            else "matching",
        },
    )


async def inventory(
    s: AsyncSession, snapshot: UUID
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, str]]:
    heads = await rows(
        s, "SELECT * FROM inventory.matching_snapshots WHERE snapshot_id=:id", id=snapshot
    )
    if not heads:
        raise JobError(ErrorCode.INVALID_PAYLOAD)
    size = (
        await s.execute(
            text(
                "SELECT coalesce(sum(octet_length(to_jsonb(p)::text)),0) FROM inve"
                "ntory.packages p WHERE snapshot_id=:id"
            ),
            {"id": snapshot},
        )
    ).scalar_one()
    count = (
        await s.execute(
            text("SELECT count(*) FROM inventory.packages WHERE snapshot_id=:id"), {"id": snapshot}
        )
    ).scalar_one()
    if size > MAX_BYTES or count > MAX_COMPONENTS:
        raise JobError(ErrorCode.INVALID_PAYLOAD)
    os = await rows(
        s, "SELECT * FROM inventory.operating_systems WHERE snapshot_id=:id", id=snapshot
    )
    kernel = await rows(s, "SELECT * FROM inventory.kernels WHERE snapshot_id=:id", id=snapshot)
    packages = await rows(
        s, "SELECT * FROM inventory.packages WHERE snapshot_id=:id ORDER BY id", id=snapshot
    )
    containers = await rows(
        s,
        (
            "SELECT * FROM inventory.containers WHERE snapshot_id=:id ORDER BY"
            " container_id LIMIT 10001"
        ),
        id=snapshot,
    )
    if len(containers) > 10000:
        raise JobError(ErrorCode.INVALID_PAYLOAD)
    values = components(packages, os[0] if os else {}, kernel[0] if kernel else {}, containers)
    bills = await rows(
        s,
        "SELECT c.*, b.document FROM inventory.container_software c "
        "LEFT JOIN inventory.software_bills b ON b.digest=c.bill_digest WHERE c.snapshot_id=:id",
        id=snapshot,
    )
    values.extend(software_components(containers, bills))
    sections = {
        r["section"]: r["status"]
        for r in await rows(
            s,
            "SELECT section,status FROM inventory.collection_sections WHERE snapshot_id=:id",
            id=snapshot,
        )
    }
    return heads[0], values, sections


async def index_revision(s: AsyncSession, revision: UUID) -> dict[str, Any]:
    try:
        values = await load_revisions(s, [revision])
    except ValueError:
        raise JobError(ErrorCode.INVALID_PAYLOAD) from None
    if not values or not values[0]["identity"].startswith("CVE-"):
        raise JobError(ErrorCode.INVALID_PAYLOAD)
    value = values[0]
    if len(value["result"].get("affected", [])) > 4096:
        raise JobError(ErrorCode.INVALID_PAYLOAD)
    keys = source_keys(value["result"].get("affected", []))
    if len(keys) > 10000:
        raise JobError(ErrorCode.INVALID_PAYLOAD)
    if keys:
        await s.execute(
            text(
                "INSERT INTO matching.vulnerability_keys SELECT :id,value FROM jso"
                "nb_array_elements_text(CAST(:keys AS jsonb)) ON CONFLICT DO NOTHI"
                "NG"
            ),
            {"id": revision, "keys": canonical(sorted(keys))},
        )
    await s.execute(
        text(
            "INSERT INTO matching.indexed_revisions VALUES(:id,:rule,:unmapped"
            ") ON CONFLICT DO NOTHING"
        ),
        {
            "id": revision,
            "rule": RULE,
            "unmapped": sum(not source_keys([a]) for a in value["result"].get("affected", [])),
        },
    )
    return value


class Service:
    def __init__(self, database: Database) -> None:
        self.database = database

    def registry(self) -> Registry:
        registry = Registry()
        for kind in [
            "index_v5_batch",
            "evaluate_v5_batch",
            "evaluate_snapshot",
            "evaluate_vulnerability",
            "evaluate_candidate_batch",
            "backfill",
            "reconcile",
        ]:
            registry.register(
                JobDefinition("matching." + kind, 1, Request, Result, self.handle, 3600, 3)
            )
        return registry

    async def handle(self, context: ExecutionContext, payload: BaseModel) -> Result:
        request = Request.model_validate(payload.model_dump())

        async def commit(s: AsyncSession) -> Result:
            kind = context.job.job_type.removeprefix("matching.")
            if request.snapshot_id is not None:
                server = await rows(
                    s,
                    "SELECT server.status FROM inventory.snapshots snap "
                    "JOIN inventory.servers server ON server.id=snap.server_id "
                    "WHERE snap.id=:id",
                    id=request.snapshot_id,
                )
                if server and server[0]["status"] != "active":
                    return Result()
            if kind in {"index_v5_batch", "evaluate_v5_batch"}:
                # Index writers run together, while snapshot candidate selection observes
                # a complete publication. Without this shared gate concurrent snapshots
                # and index batches could each miss the other's not-yet-committed input.
                await s.execute(text("SELECT pg_advisory_xact_lock_shared(170017)"))
                return await self.v5_batch(s, context, request)
            if kind != "evaluate_candidate_batch":
                await s.execute(text("SELECT pg_advisory_xact_lock(170017)"))
            if kind == "evaluate_candidate_batch":
                return await self.evaluate(s, context, request)
            if kind == "evaluate_snapshot":
                return await self.snapshot(s, context, request)
            if kind == "evaluate_vulnerability":
                return await self.vulnerability(s, context, request)
            return await self.backfill(s, context, request)

        result = await context.complete(commit)
        assert isinstance(result, Result)
        return result

    async def v5_batch(self, s: AsyncSession, ctx: ExecutionContext, req: Request) -> Result:
        if not req.revisions or len(set(req.revisions)) != len(req.revisions):
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        try:
            documents = await load_revisions(s, req.revisions)
        except ValueError as error:
            if str(error) == "revision_context_bytes" and len(req.revisions) > 1:
                return await self.split_v5_batch(s, ctx, req)
            raise JobError(ErrorCode.INVALID_PAYLOAD) from None
        if len(documents) != len(req.revisions):
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        index: list[dict[str, Any]] = []
        keys: list[dict[str, str]] = []
        for document in documents:
            affected = document["result"].get("affected", [])
            if not document["identity"].startswith("CVE-") or len(affected) > 4096:
                raise JobError(ErrorCode.INVALID_PAYLOAD)
            native_keys = source_keys(affected)
            if len(native_keys) > 10000:
                raise JobError(ErrorCode.INVALID_PAYLOAD)
            index.append(
                {"id": str(document["id"]), "unmapped": sum(not source_keys([a]) for a in affected)}
            )
            keys.extend({"id": str(document["id"]), "key": key} for key in sorted(native_keys))
            if len(keys) > 50000 and len(req.revisions) > 1:
                return await self.split_v5_batch(s, ctx, req)
        await s.execute(
            text("""
INSERT INTO matching.vulnerability_keys(enrichment_revision_id,key)
SELECT d.id,d.key FROM jsonb_to_recordset(CAST(:rows AS jsonb)) d(id uuid,key text)
ORDER BY d.id,d.key ON CONFLICT DO NOTHING
"""),
            {"rows": canonical(keys)},
        )
        await s.execute(
            text("""
INSERT INTO matching.indexed_revisions(enrichment_revision_id,rule_version,unmapped_count)
SELECT d.id,:rule,d.unmapped FROM jsonb_to_recordset(CAST(:rows AS jsonb))
 d(id uuid,unmapped integer)
ORDER BY d.id ON CONFLICT DO NOTHING
"""),
            {"rows": canonical(index), "rule": RULE},
        )
        if ctx.job.job_type == "matching.index_v5_batch" and await centrally_controlled(s):
            await enqueue(
                s, "evaluate_v5_batch", req, str(ctx.job.id) + ":indexed", ctx.job.correlation_id
            )
            return Result(count=len(documents))
        # Only current handles produce candidates; stale queued batches cannot republish old data.
        candidates = await rows(
            s,
            """
WITH current AS MATERIALIZED (
 SELECT identity,current_revision_id AS revision FROM cve.enrichment_identities
 WHERE current_revision_id=ANY(:ids)
), candidates AS (
 SELECT c.identity,c.revision,i.server_id,i.snapshot_id FROM current c
 JOIN matching.vulnerability_keys v ON v.enrichment_revision_id=c.revision
 JOIN matching.inventory_keys k ON k.key=v.key
 JOIN inventory.server_current_snapshots i ON i.snapshot_id=k.snapshot_id
 JOIN inventory.servers server ON server.id=i.server_id AND server.status='active'
 UNION
 SELECT c.identity,c.revision,i.server_id,i.snapshot_id FROM current c
 JOIN matching.current_results old ON old.identity=c.identity
 JOIN inventory.server_current_snapshots i ON i.server_id=old.server_id
 JOIN inventory.servers server ON server.id=i.server_id AND server.status='active'
)
SELECT *,identity||':'||server_id::text AS cursor FROM candidates
WHERE identity||':'||server_id::text>:after ORDER BY cursor LIMIT :limit
""",
            ids=req.revisions,
            after=req.after,
            limit=PAGE,
        )
        for candidate in candidates:
            await enqueue(
                s,
                "evaluate_candidate_batch",
                Request(
                    snapshot_id=candidate["snapshot_id"],
                    enrichment_revision_id=candidate["revision"],
                    identity=candidate["identity"],
                ),
                str(ctx.job.id) + candidate["cursor"],
                ctx.job.correlation_id,
            )
        if len(candidates) == PAGE:
            await enqueue(
                s,
                ctx.job.job_type.removeprefix("matching."),
                req.model_copy(update={"after": candidates[-1]["cursor"]}),
                str(ctx.job.id) + ":next",
                ctx.job.correlation_id,
                technical=True,
            )
        return Result(count=len(documents))

    async def split_v5_batch(self, s: AsyncSession, ctx: ExecutionContext, req: Request) -> Result:
        """Large valid documents get smaller durable jobs, never a silently dropped package."""
        middle = len(req.revisions) // 2
        for position, ids in enumerate((req.revisions[:middle], req.revisions[middle:])):
            await enqueue(
                s,
                ctx.job.job_type.removeprefix("matching."),
                req.model_copy(update={"revisions": ids}),
                str(ctx.job.id) + ":split:" + str(position),
                ctx.job.correlation_id,
                technical=True,
            )
        return Result()

    async def snapshot(self, s: AsyncSession, ctx: ExecutionContext, req: Request) -> Result:
        if req.snapshot_id is None:
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        head, values, _ = await inventory(s, req.snapshot_id)
        keys = sorted({key for c in values for key in component_keys(c)})
        if keys:
            await s.execute(
                text(
                    "INSERT INTO matching.inventory_keys SELECT :id,value FROM jsonb_a"
                    "rray_elements_text(CAST(:keys AS jsonb)) ON CONFLICT DO NOTHING"
                ),
                {"id": req.snapshot_id, "keys": canonical(keys)},
            )
        # Previous results are candidates even if a component has disappeared.
        candidates = await rows(
            s,
            """SELECT identity,id FROM (
 SELECT e.identity,e.current_revision_id AS id FROM matching.inventory_keys i
 JOIN matching.vulnerability_keys v ON v.key=i.key
 JOIN cve.enrichment_identities e ON e.current_revision_id=v.enrichment_revision_id
 WHERE i.snapshot_id=:snapshot AND e.kind='cve'
 UNION
 SELECT e.identity,e.current_revision_id AS id FROM matching.current_results c
 JOIN cve.enrichment_identities e ON e.identity=c.identity
 WHERE c.server_id=:server AND e.current_revision_id IS NOT NULL
) candidates WHERE identity>:after ORDER BY identity LIMIT :limit""",
            after=req.after,
            snapshot=req.snapshot_id,
            server=head["server_id"],
            limit=PAGE,
        )
        for candidate in candidates:
            await enqueue(
                s,
                "evaluate_candidate_batch",
                Request(
                    snapshot_id=req.snapshot_id,
                    enrichment_revision_id=candidate["id"],
                    identity=candidate["identity"],
                ),
                str(ctx.job.id) + candidate["identity"],
                ctx.job.correlation_id,
            )
        if len(candidates) == PAGE:
            await enqueue(
                s,
                "evaluate_snapshot",
                req.model_copy(update={"after": candidates[-1]["identity"]}),
                str(ctx.job.id) + ":next",
                ctx.job.correlation_id,
            )
        return Result(count=len(candidates))

    async def vulnerability(self, s: AsyncSession, ctx: ExecutionContext, req: Request) -> Result:
        revision = req.enrichment_revision_id
        if revision is None and req.identity:
            heads = await rows(
                s,
                (
                    "SELECT current_revision_id AS id FROM cve.enrichment_identities W"
                    "HERE identity=:identity"
                ),
                identity=req.identity,
            )
            revision = heads[0]["id"] if heads else None
        if revision is None:
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        value = await index_revision(s, revision)
        candidates = await rows(
            s,
            """SELECT server_id,snapshot_id FROM (
 SELECT c.server_id,c.snapshot_id FROM matching.vulnerability_keys v
 JOIN matching.inventory_keys i ON i.key=v.key
 JOIN inventory.server_current_snapshots c ON c.snapshot_id=i.snapshot_id
 JOIN inventory.servers server ON server.id=c.server_id AND server.status='active'
 WHERE v.enrichment_revision_id=:revision
 UNION
 SELECT c.server_id,c.snapshot_id FROM matching.current_results old
 JOIN inventory.server_current_snapshots c ON c.server_id=old.server_id
 JOIN inventory.servers server ON server.id=c.server_id AND server.status='active'
 WHERE old.identity=:identity
) candidates WHERE server_id::text>:after ORDER BY server_id::text LIMIT :limit""",
            after=req.after,
            revision=revision,
            identity=value["identity"],
            limit=PAGE,
        )
        for candidate in candidates:
            await enqueue(
                s,
                "evaluate_candidate_batch",
                Request(
                    snapshot_id=candidate["snapshot_id"],
                    enrichment_revision_id=revision,
                    identity=value["identity"],
                ),
                str(ctx.job.id) + str(candidate["server_id"]),
                ctx.job.correlation_id,
            )
        if len(candidates) == PAGE:
            following = req.model_copy(
                update={
                    "after": str(candidates[-1]["server_id"]),
                    "enrichment_revision_id": revision,
                }
            )
            await enqueue(
                s,
                "evaluate_vulnerability",
                following,
                str(ctx.job.id) + ":next",
                ctx.job.correlation_id,
            )
        return Result(count=len(candidates))

    async def backfill(self, s: AsyncSession, ctx: ExecutionContext, req: Request) -> Result:
        if req.stage == "revisions":
            values = await rows(
                s,
                (
                    "SELECT identity,current_revision_id AS id FROM cve.enrichment_ide"
                    "ntities WHERE kind='cve' AND identity>:after AND current_revision"
                    "_id IS NOT NULL ORDER BY identity LIMIT :limit"
                ),
                after=req.after,
                limit=PAGE,
            )
            for value in values:
                await index_revision(s, value["id"])
            following = (
                req.model_copy(update={"after": values[-1]["identity"]})
                if len(values) == PAGE
                else Request(stage="snapshots")
            )
            await enqueue(
                s, "backfill", following, str(ctx.job.id) + ":next", ctx.job.correlation_id
            )
        else:
            values = await rows(
                s,
                (
                    "SELECT c.server_id,c.snapshot_id FROM inventory.server_current_snapshots c "
                    "JOIN inventory.servers server ON server.id=c.server_id "
                    "AND server.status='active' "
                    "WHERE c.server_id::text>:after ORDER BY c.server_id::text LIMIT :"
                    "limit"
                ),
                after=req.after,
                limit=PAGE,
            )
            for value in values:
                await enqueue(
                    s,
                    "evaluate_snapshot",
                    Request(snapshot_id=value["snapshot_id"]),
                    str(ctx.job.id) + str(value["snapshot_id"]),
                    ctx.job.correlation_id,
                )
            if len(values) == PAGE:
                await enqueue(
                    s,
                    "backfill",
                    req.model_copy(update={"after": str(values[-1]["server_id"])}),
                    str(ctx.job.id) + ":next",
                    ctx.job.correlation_id,
                )
        return Result(count=len(values))

    async def evaluate(self, s: AsyncSession, ctx: ExecutionContext, req: Request) -> Result:
        if req.snapshot_id is None or req.enrichment_revision_id is None:
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        head, values, sections = await inventory(s, req.snapshot_id)
        revision = await index_revision(s, req.enrichment_revision_id)
        if req.identity is not None and req.identity != revision["identity"]:
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        fingerprint = digest([str(req.snapshot_id), str(req.enrichment_revision_id), RULE])
        await s.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
            {"key": "matching-input:" + fingerprint},
        )
        old = await rows(
            s,
            (
                "SELECT id FROM matching.result_revisions WHERE server_id=:server "
                "AND identity=:identity AND fingerprint=decode(:hash,'hex')"
            ),
            server=head["server_id"],
            identity=revision["identity"],
            hash=fingerprint,
        )
        if old:
            changed = (
                await s.execute(
                    text("SELECT matching.publish(:id,:correlation)"),
                    {"id": old[0]["id"], "correlation": ctx.job.correlation_id},
                )
            ).scalar_one()
            return Result(revision_id=old[0]["id"], changed=changed)
        try:
            evaluation = await asyncio.to_thread(evaluate, revision["result"], values, sections)
        except EvaluationLimit:
            raise JobError(ErrorCode.INVALID_PAYLOAD) from None
        encoded_result = evaluation.model_dump_json()
        if len(encoded_result.encode()) > MAX_BYTES:
            raise JobError(ErrorCode.INVALID_PAYLOAD)
        run, result = uuid4(), uuid4()
        await s.execute(
            text(
                "INSERT INTO matching.runs(id,snapshot_id,server_id,rule_version,s"
                "ource_set_hash,job_id,correlation_id,trigger_type) VALUES(:id,:sn"
                "apshot,:server,:rule,decode(:hash,'hex'),:job,:correlation,:trigg"
                "er)"
            ),
            {
                "id": run,
                "snapshot": req.snapshot_id,
                "server": head["server_id"],
                "rule": RULE,
                "hash": fingerprint,
                "job": ctx.job.id,
                "correlation": ctx.job.correlation_id,
                "trigger": ctx.job.job_type,
            },
        )
        await s.execute(
            text("INSERT INTO matching.run_inputs VALUES(:run,:revision,:identity)"),
            {"run": run, "revision": req.enrichment_revision_id, "identity": revision["identity"]},
        )
        await s.execute(
            text(
                "INSERT INTO matching.candidates VALUES(:run,:revision,:identity,C"
                "AST(:keys AS jsonb))"
            ),
            {
                "run": run,
                "revision": req.enrichment_revision_id,
                "identity": revision["identity"],
                "keys": canonical(sorted(source_keys(revision["result"].get("affected", [])))),
            },
        )
        await s.execute(
            text(
                "INSERT INTO matching.result_revisions(id,run_id,server_id,snapsho"
                "t_id,identity,enrichment_revision_id,rule_version,fingerprint,sta"
                "tus,reason,result) VALUES(:id,:run,:server,:snapshot,:identity,:r"
                "evision,:rule,decode(:hash,'hex'),:status,:reason,CAST(:result AS"
                " jsonb))"
            ),
            {
                "id": result,
                "run": run,
                "server": head["server_id"],
                "snapshot": req.snapshot_id,
                "identity": revision["identity"],
                "revision": req.enrichment_revision_id,
                "rule": RULE,
                "hash": fingerprint,
                "status": evaluation.status,
                "reason": evaluation.reason,
                "result": encoded_result,
            },
        )
        package_ids = {
            c["id"] for c in values if c["kind"] == "package" and c.get("context") == "host"
        }
        entries = [
            {
                "id": result,
                "position": i,
                "component": d.component_id,
                "context": d.context,
                "snapshot": req.snapshot_id,
                "package": UUID(d.component_id) if d.component_id in package_ids else None,
                "value": d.model_dump_json(),
            }
            for i, d in enumerate(evaluation.components)
        ]
        for offset in range(0, len(entries), 500):
            await s.execute(
                text(
                    "INSERT INTO matching.component_results VALUES(:id,:position,:comp"
                    "onent,:context,:snapshot,:package,CAST(:value AS jsonb))"
                ),
                entries[offset : offset + 500],
            )
        evidence = [e for d in evaluation.components for e in d.evidence]
        conflicts = [e for d in evaluation.components for e in d.conflicts]
        for table, entries in [("result_evidence", evidence), ("result_conflicts", conflicts)]:
            if entries:
                await s.execute(
                    text(
                        "INSERT INTO matching."
                        + table
                        + " VALUES(:id,:position,CAST(:value AS jsonb))"
                    ),
                    [
                        {"id": result, "position": i, "value": canonical(e)}
                        for i, e in enumerate(entries)
                    ],
                )
        await s.execute(
            text("INSERT INTO matching.coverage VALUES(:id,CAST(:value AS jsonb))"),
            {"id": result, "value": canonical(evaluation.coverage)},
        )
        changed = (
            await s.execute(
                text("SELECT matching.publish(:id,:correlation)"),
                {"id": result, "correlation": ctx.job.correlation_id},
            )
        ).scalar_one()
        await s.execute(
            text(
                "UPDATE matching.runs SET status='succeeded',completed_at=clock_ti"
                "mestamp() WHERE id=:id"
            ),
            {"id": run},
        )
        return Result(count=1, revision_id=result, changed=changed)
