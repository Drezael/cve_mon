"""Read native V5 documents; derive matching/priority fields only when needed."""

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cve_common.cvss import metric, provenance

MAX_BYTES = 33554432


def project(
    identity: str,
    document: dict[str, Any],
    revision: UUID,
    present: bool,
    *,
    include_cvss: bool = False,
) -> dict[str, Any]:
    """Transient projection: native products and version semantics remain intact."""
    row = {"source_id": "cve_list", "external_id": identity, "revision_id": revision}
    state = document.get("cveMetadata", {}).get("state")
    value = {"PUBLISHED": "published", "REJECTED": "rejected"}.get(state, "unknown")
    result: dict[str, Any] = {
        "identity": identity,
        "lifecycle": {
            "value": value if present else "withdrawn",
            "provenance": provenance(row, "/cveMetadata/state", "official-cve-status-only"),
        },
        "affected": [],
        "relations": [],
        "conflicts": [],
        "cvss": [],
        "kev": {"status": "unknown", "reason": "not_configured", "provenance": None},
    }
    containers = document.get("containers", {})
    for container, path in [
        (containers.get("cna", {}), "/containers/cna"),
        *[(v, f"/containers/adp/{i}") for i, v in enumerate(containers.get("adp", []))],
    ]:
        for i, affected in enumerate(container.get("affected", [])):
            result["affected"].append(
                {
                    "kind": "cna_product",
                    "value": affected,
                    "association": "explicit",
                    "matching_usable": present,
                    "comparison": "deferred_to_phase17",
                    "provenance": provenance(
                        row, f"{path}/affected/{i}", "preserve-native-version-semantics"
                    ),
                }
            )
        if include_cvss:
            for i, assessment in enumerate(container.get("metrics", [])):
                for key, assessment_value in assessment.items():
                    if key.startswith("cvss") and isinstance(assessment_value, dict):
                        result["cvss"].append(
                            metric(
                                assessment_value,
                                row,
                                f"{path}/metrics/{i}/{key}",
                                container.get("providerMetadata", {}).get("orgId", ""),
                            )
                        )
    valid = [m for m in result["cvss"] if m["validation_status"] == "valid"]
    if valid:
        preferred = min(
            valid,
            key=lambda m: (
                {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}[m["cvss_version"]],
                str(m["metric_provider"]),
                str(m["vector_string"]),
            ),
        )
        preferred["is_preferred"] = True
    return result


async def revisions(
    session: AsyncSession, ids: list[UUID], *, include_cvss: bool = False
) -> list[dict[str, Any]]:
    """Bound document reads and preserve historical normalized revisions unchanged."""
    if not 1 <= len(ids) <= 128:
        raise ValueError("revision_batch_limit")
    rows = (
        (
            await session.execute(
                text("""
WITH bounded AS MATERIALIZED (
 SELECT e.id,e.identity,e.result,d.source_revision_id,d.document_present,d.document,
  COALESCE(octet_length(d.document::text),octet_length(e.result::text)) AS bytes
 FROM cve.enrichment_revisions e LEFT JOIN cve.v5_revision_documents d ON d.id=e.id
 WHERE e.id=ANY(:ids)
), sized AS (SELECT *,sum(bytes) OVER() AS total FROM bounded)
SELECT id,identity,CASE WHEN total<=:maximum THEN result ELSE NULL END AS result,
 source_revision_id,document_present,
 CASE WHEN total<=:maximum THEN cve.v5_projection(document,:cvss) ELSE NULL END AS document,
 bytes FROM sized
"""),
                {"ids": ids, "maximum": MAX_BYTES, "cvss": include_cvss},
            )
        )
        .mappings()
        .all()
    )
    if sum(r["bytes"] for r in rows) > MAX_BYTES:
        raise ValueError("revision_context_bytes")
    result = []
    for row in rows:
        value = dict(row)
        if value["result"].get("storage") == "v5-json":
            if value["document"] is None:
                raise ValueError("missing_v5_document")
            value["result"] = project(
                value["identity"],
                value["document"],
                value["source_revision_id"],
                value["document_present"],
                include_cvss=include_cvss,
            )
        result.append({k: value[k] for k in ("id", "identity", "result")})
    return result
