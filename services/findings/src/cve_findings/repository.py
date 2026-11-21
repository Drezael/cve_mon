"""Short fenced transactions over immutable matching publications and finding identity."""

import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

from cve_common.jobs.errors import ErrorCode, JobError
from cve_common.v5 import revisions as load_revisions
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_findings.contracts import Policy, Result, Signals
from cve_findings.rules import deadline, lifecycle, priority, resolution


async def rows(s: AsyncSession, sql: str, **params: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in (await s.execute(text(sql), params)).mappings()]


async def one(s: AsyncSession, sql: str, **params: Any) -> dict[str, Any] | None:
    values = await rows(s, sql, **params)
    return values[0] if values else None


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, allow_nan=False)


def digest(value: Any) -> bytes:
    return hashlib.sha256(canonical(value).encode()).digest()


async def active_policy(s: AsyncSession) -> tuple[UUID, Policy]:
    row = await one(
        s,
        (
            "SELECT p.id,p.configuration FROM findings.policy_versions p JOIN findings.acti"
            "ve_policy a ON a.policy_id=p.id"
        ),
    )
    assert row is not None
    return row["id"], Policy.model_validate(row["configuration"])


async def record(
    s: AsyncSession, finding: UUID, kind: str, old: dict[str, Any], reason: str, correlation: UUID
) -> None:
    await s.execute(
        text(
            "SELECT findings.record_change(:id,:kind,CAST(:old AS jsonb),:reason,:corre"
            "lation,NULL,NULL)"
        ),
        {
            "id": finding,
            "kind": kind,
            "old": canonical(old),
            "reason": reason,
            "correlation": correlation,
        },
    )


async def signals(s: AsyncSession, identity: str) -> Signals:
    row = await one(
        s,
        "SELECT id,result,kev_status,kev_is_current FROM cve.current_enrichment WHERE identity=:id",
        id=identity,
    )
    if row and row["result"].get("storage") == "v5-json":
        row["result"] = (await load_revisions(s, [row["id"]], include_cvss=True))[0]["result"]
        risk = await one(s, "SELECT cve.kev_risk(:identity) AS value", identity=identity)
        assert risk
        row["kev_status"] = risk["value"]["status"]
        row["kev_is_current"] = risk["value"]["is_current"]
        row["result"]["kev"] = {"entry": {"value": {"dueDate": risk["value"].get("due_date")}}}

    epss = await one(
        s,
        (
            "SELECT dataset_id,score_date,model_version,score,percentile,age_days,is_stale "
            "FROM cve.current_epss_scores WHERE cve_id=:id"
        ),
        id=identity,
    )
    cvss = (
        next(
            (
                v
                for v in row["result"].get("cvss", [])
                if v.get("validation_status") == "valid" and v.get("is_preferred")
            ),
            None,
        )
        if row
        else None
    )
    # Retain the actual metric/provider/vector; no raw CVE/inventory payload in events.
    return Signals(
        enrichment_revision_id=row["id"] if row else None,
        cvss=cvss,
        kev_status=row["kev_status"] if row else "unknown",
        kev_is_current=bool(row and row["kev_is_current"]),
        kev_due_date=row["result"].get("kev", {}).get("entry", {}).get("value", {}).get("dueDate")
        if row and row["result"].get("kev", {}).get("entry")
        else None,
        epss=json.loads(canonical(epss)) if epss else None,
    )


async def reprioritize(
    s: AsyncSession, finding: dict[str, Any], correlation: UUID, *, initial: bool = False
) -> bool:
    pid, policy = await active_policy(s)
    signal = await signals(s, finding["cve_id"])
    level, reasons = priority(signal, policy)
    basis = signal.model_dump(mode="json")
    fingerprint = digest([str(pid), str(finding["current_episode_id"]), basis, level, reasons])
    episode = await one(
        s, "SELECT opened_at FROM findings.episodes WHERE id=:id", id=finding["current_episode_id"]
    )
    assert episode is not None
    old_deadline = await one(
        s, "SELECT due_at FROM findings.deadlines WHERE id=:id", id=finding["current_deadline_id"]
    )
    due = deadline(
        episode["opened_at"], level, policy, old_deadline["due_at"] if old_deadline else None
    )
    if finding["status"] in {"resolved", "closed"}:
        due = old_deadline["due_at"] if old_deadline else None
    if fingerprint == finding["priority_fingerprint"] and (
        due is None or old_deadline and due == old_deadline["due_at"]
    ):
        return False
    await s.execute(
        text(
            "INSERT INTO findings.priority_history(finding_id,episode_id,priority,polic"
            "y_id,signals,reasons,fingerprint) VALUES(:id,:episode,:level,:policy,CAST("
            ":signals AS jsonb),CAST(:reasons AS jsonb),:hash)"
        ),
        {
            "id": finding["id"],
            "episode": finding["current_episode_id"],
            "level": level,
            "policy": pid,
            "signals": canonical(basis),
            "reasons": canonical(reasons),
            "hash": fingerprint,
        },
    )
    deadline_id = finding["current_deadline_id"]
    if due is not None and (not old_deadline or due != old_deadline["due_at"]):
        deadline_id = uuid4()
        await s.execute(
            text(
                "INSERT INTO findings.deadlines(id,finding_id,episode_id,policy_id,due_"
                "at,anchor_at,priority,reason) VALUES(:deadline,:id,:episode,:policy,:d"
                "ue,:anchor,:priority,'approved_policy')"
            ),
            {
                "deadline": deadline_id,
                "id": finding["id"],
                "episode": finding["current_episode_id"],
                "policy": pid,
                "due": due,
                "anchor": episode["opened_at"],
                "priority": level,
            },
        )
    old = dict(finding)
    await s.execute(
        text(
            "UPDATE findings.findings SET current_priority=:priority,priority_basis=CAS"
            "T(:basis AS jsonb),priority_fingerprint=:hash,current_deadline_id=:deadlin"
            "e,version=version+1 WHERE id=:id"
        ),
        {
            "priority": level,
            "basis": canonical(basis),
            "hash": fingerprint,
            "deadline": deadline_id,
            "id": finding["id"],
        },
    )
    finding.update(
        current_priority=level,
        priority_basis=basis,
        priority_fingerprint=fingerprint,
        current_deadline_id=deadline_id,
        version=finding["version"] + 1,
    )
    if not initial:
        await record(
            s,
            finding["id"],
            "priority_changed" if level != old["current_priority"] else "updated",
            old,
            "risk_evidence_updated",
            correlation,
        )
    return True


async def observe(
    s: AsyncSession,
    finding: dict[str, Any],
    match: dict[str, Any],
    publication: int,
    *,
    historical: bool,
) -> None:
    await s.execute(
        text(
            "INSERT INTO findings.match_observations(finding_id,episode_id,result_id,pu"
            "blication_version,is_historical,snapshot_captured_at,matched_at) VALUES(:i"
            "d,:episode,:result,:publication,:historical,:captured,:matched) ON CONFLIC"
            "T(finding_id,publication_version) DO NOTHING"
        ),
        {
            "id": finding["id"],
            "episode": None if historical else finding["current_episode_id"],
            "result": match["id"],
            "publication": publication,
            "historical": historical,
            "captured": match["captured_at"],
            "matched": match["created_at"],
        },
    )


async def technical_changed(s: AsyncSession, previous: UUID, match: dict[str, Any]) -> bool:
    old = await one(
        s,
        (
            "SELECT r.snapshot_id,r.rule_version,r.status,r.result,e.result->'affected' AS "
            "affected,e.result->'lifecycle' AS lifecycle,e.id AS document_id "
            "FROM matching.result_revisions r J"
            "OIN cve.enrichment_revisions e ON e.id=r.enrichment_revision_id WHERE r.id=:id"
        ),
        id=previous,
    )
    new = await one(
        s,
        (
            "SELECT result->'affected' AS affected,result->'lifecycle' AS lifecycle FROM cv"
            "e.enrichment_revisions WHERE id=:id"
        ),
        id=match["enrichment_revision_id"],
    )
    if not old or not new:
        return True

    for row, revision in ((old, old["document_id"]), (new, match["enrichment_revision_id"])):
        document = (await load_revisions(s, [revision]))[0]["result"]
        row["affected"], row["lifecycle"] = document.get("affected"), document.get("lifecycle")

    def semantic(row: dict[str, Any]) -> Any:
        components = [
            {k: v for k, v in c.items() if k not in {"evidence", "conflicts"}}
            for c in row["result"].get("components", [])
        ]
        affected = [
            {k: v for k, v in a.items() if k != "provenance"} for a in row.get("affected") or []
        ]
        return [
            str(row["snapshot_id"]),
            row["rule_version"],
            row["status"],
            components,
            affected,
            (row.get("lifecycle") or {}).get("value"),
        ]

    return digest(semantic(old)) != digest(semantic(match | new))


async def apply(
    s: AsyncSession, result: UUID, publication: int, correlation: UUID
) -> tuple[Result, str]:
    match = await one(
        s,
        (
            "SELECT r.*,snap.captured_at,run.status AS run_status FROM matching.result_revi"
            "sions r JOIN inventory.snapshots snap ON snap.id=r.snapshot_id JOIN matching.r"
            "uns run ON run.id=r.run_id WHERE r.id=:id"
        ),
        id=result,
    )
    if match is None:
        raise JobError(ErrorCode.INVALID_PAYLOAD)
    await s.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key,18))"),
        {"key": str(match["server_id"]) + ":" + match["identity"]},
    )
    finding = await one(
        s,
        (
            "SELECT * FROM findings.findings WHERE server_id=:server AND cve_id=:identity A"
            "ND model_version=2 FOR UPDATE"
        ),
        server=match["server_id"],
        identity=match["identity"],
    )
    current = bool(
        (
            await s.execute(
                text("SELECT findings.lock_current(:id,:version)"),
                {"id": result, "version": publication},
            )
        ).scalar_one()
    )
    match["is_current"] = current
    can_open = match["status"] == "affected" or (
        match["status"] == "potentially_affected" and bool(match["result"].get("components"))
    )
    now = (await s.execute(text("SELECT clock_timestamp()"))).scalar_one()
    initial = finding is None
    if initial:
        if not current or not can_open:
            return Result(), "stale" if not current else "no_candidate"
        finding_id, episode_id = uuid4(), uuid4()
        await s.execute(
            text(
                "INSERT INTO findings.findings(id,server_id,cve_id,enrichment_identity,"
                "status,risk_level,model_version,latest_matching_result_id,latest_match"
                "ing_status,matching_version,current_episode_id,first_seen_at,last_conf"
                "irmed_at,last_evaluated_at) VALUES(:id,:server,:identity,:identity,'op"
                "en','unknown',2,:result,:status,:publication,:episode,:now,:confirmed,"
                ":evaluated)"
            ),
            {
                "id": finding_id,
                "server": match["server_id"],
                "identity": match["identity"],
                "result": result,
                "status": match["status"],
                "publication": publication,
                "episode": episode_id,
                "now": now,
                "confirmed": now if match["status"] == "affected" else None,
                "evaluated": match["created_at"],
            },
        )
        await s.execute(
            text(
                "INSERT INTO findings.episodes(id,finding_id,number,opened_at,first_res"
                "ult_id) VALUES(:id,:finding,1,:now,:result)"
            ),
            {"id": episode_id, "finding": finding_id, "now": now, "result": result},
        )
        finding = await one(s, "SELECT * FROM findings.findings WHERE id=:id", id=finding_id)
        assert finding is not None
    assert finding is not None
    if finding["matching_version"] >= publication and not initial:
        await observe(s, finding, match, publication, historical=not current)
        return Result(finding_id=finding["id"]), "duplicate" if finding[
            "matching_version"
        ] == publication else "stale"
    if not current:
        await observe(s, finding, match, publication, historical=True)
        return Result(finding_id=finding["id"]), "stale"
    old = dict(finding)
    pid, policy = await active_policy(s)
    qualified = resolution(match, policy, now)
    changed_technical = True
    if not initial and finding["review_state"] in {
        "confirmed_false_positive",
        "suspected_false_positive",
        "mitigation_documented",
    }:
        changed_technical = await technical_changed(s, finding["latest_matching_result_id"], match)
    transition_status = match["status"] if changed_technical else "unknown"
    state, reopened = lifecycle(finding["status"], transition_status, qualified_fix=qualified)
    kind = "created" if initial else "updated"
    episode_id = finding["current_episode_id"]
    if reopened:
        number = (
            await s.execute(
                text("SELECT max(number)+1 FROM findings.episodes WHERE finding_id=:id"),
                {"id": finding["id"]},
            )
        ).scalar_one()
        episode_id = uuid4()
        await s.execute(
            text(
                "INSERT INTO findings.episodes(id,finding_id,number,opened_at,first_res"
                "ult_id,reopening_reason) VALUES(:id,:finding,:number,:now,:result,'con"
                "firmed_recurrence')"
            ),
            {
                "id": episode_id,
                "finding": finding["id"],
                "number": number,
                "now": now,
                "result": result,
            },
        )
        kind = "reopened"
    elif state == "resolved" and finding["status"] != "resolved":
        await s.execute(
            text(
                "INSERT INTO findings.episode_closures(episode_id,result_id,policy_id,r"
                "eason) VALUES(:episode,:result,:policy,'qualified_current_fix') ON CON"
                "FLICT DO NOTHING"
            ),
            {"episode": episode_id, "result": result, "policy": pid},
        )
        kind = "resolved"
    elif match["status"] in {"unknown", "not_applicable"} or (
        finding["review_state"]
        in {"confirmed_false_positive", "suspected_false_positive", "mitigation_documented"}
        and result != finding["latest_matching_result_id"]
        and changed_technical
    ):
        kind = "review_required"
    observation_finding = dict(finding)
    observation_finding["current_episode_id"] = episode_id
    await observe(s, observation_finding, match, publication, historical=False)
    review = "needs_review" if reopened or kind == "review_required" else finding["review_state"]
    await s.execute(
        text(
            "UPDATE findings.findings SET status=:state,latest_matching_result_id=:resu"
            "lt,latest_matching_status=:technical,matching_version=:publication,current"
            "_episode_id=:episode,last_confirmed_at=:confirmed,last_evaluated_at=:evalu"
            "ated,resolved_at=:resolved,closed_at=:closed,resolution_result_id=:proof,r"
            "eview_state=:review,assignee_user_id=:assignee,current_deadline_id=:deadli"
            "ne,version=version+1 WHERE id=:id"
        ),
        {
            "state": state,
            "result": result,
            "technical": match["status"],
            "publication": publication,
            "episode": episode_id,
            "confirmed": now if match["status"] == "affected" else finding["last_confirmed_at"],
            "evaluated": match["created_at"],
            "resolved": now if kind == "resolved" else None if reopened else finding["resolved_at"],
            "closed": None if reopened else finding["closed_at"],
            "proof": result
            if kind == "resolved"
            else None
            if reopened
            else finding["resolution_result_id"],
            "review": review,
            "assignee": None if reopened else finding["assignee_user_id"],
            "deadline": None if reopened else finding["current_deadline_id"],
            "id": finding["id"],
        },
    )
    updated = await one(s, "SELECT * FROM findings.findings WHERE id=:id", id=finding["id"])
    assert updated is not None
    await reprioritize(s, updated, correlation, initial=True)
    if not initial and updated["current_priority"] != old["current_priority"]:
        await record(
            s, finding["id"], "priority_changed", old, "matching_risk_evidence_updated", correlation
        )
    await record(
        s, finding["id"], kind, {} if initial else old, "matching_publication_applied", correlation
    )
    # Extra typed signals share the committed row version, each has its own event identity.
    if initial and match["status"] in {"affected", "potentially_affected"}:
        await record(
            s,
            finding["id"],
            "confirmed_affected" if match["status"] == "affected" else "potentially_affected",
            old,
            "initial_matching_status",
            correlation,
        )
    return Result(count=1, finding_id=finding["id"], changed=True), "applied"
