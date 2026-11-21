"""Pure versioned source rules: preserve all evidence, never perform server matching."""

import hashlib
import json
import re
from typing import Any

from cve_common.cvss import metric as metric

from cve_enricher.contracts import RULE

CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
RANK = {"cve_list": 0, "nvd": 1, "ubuntu": 2, "osv": 3, "cisa_kev": 4}


def canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def provenance(row: dict[str, Any], pointer: str, rule: str) -> dict[str, Any]:
    return {
        "source_id": row["source_id"],
        "external_id": row["external_id"],
        "source_revision_id": str(row["revision_id"]),
        "json_pointer": pointer,
        "rule": rule,
        "rule_version": RULE,
    }


def normalize(identity: str, rows: list[dict[str, Any]], kev: dict[str, Any]) -> dict[str, Any]:
    rows = sorted(
        rows, key=lambda r: (RANK.get(r["source_id"], 99), r["external_id"], str(r["revision_id"]))
    )
    out: dict[str, Any] = {
        "identity": identity,
        "identity_kind": "cve" if CVE.fullmatch(identity) else "advisory",
        "rule_version": RULE,
        "lifecycle": {"value": "unknown", "provenance": None},
        "descriptions": [],
        "dates": [],
        "weaknesses": [],
        "references": [],
        "relations": [],
        "cvss": [],
        "affected": [],
        "conflicts": [],
        "kev": kev,
        "inputs": [
            {
                "revision_id": str(r["revision_id"]),
                "source_id": r["source_id"],
                "external_id": r["external_id"],
            }
            for r in rows
        ],
    }
    for row in rows:
        raw = row["original_json"]
        source = row["source_id"]
        aliases = sorted(set(row.get("identifiers", [])) - {row["external_id"]})
        cves = [a for a in aliases if CVE.fullmatch(a)]
        ambiguous = len(cves) > 1
        for alias in aliases:
            out["relations"].append(
                {
                    "origin": row["external_id"],
                    "target": alias,
                    "relation_type": "references" if source == "ubuntu" else "alias_of",
                    "validation_status": "ambiguous" if ambiguous else "explicit",
                    "provenance": provenance(
                        row,
                        ("/cves_ids" if "cves_ids" in raw else "/cves")
                        if source == "ubuntu"
                        else "/aliases",
                        "explicit-source-relationship",
                    ),
                }
            )
        for field, relation in [("related", "related_to"), ("upstream", "upstream_of")]:
            for target in raw.get(field, []):
                if isinstance(target, str):
                    out["relations"].append(
                        {
                            "origin": row["external_id"],
                            "target": target,
                            "relation_type": relation,
                            "validation_status": "source_asserted",
                            "provenance": provenance(
                                row, "/" + field, "no-equivalence-from-reference"
                            ),
                        }
                    )
        if ambiguous:
            out["conflicts"].append(
                {
                    "kind": "multi_cve_advisory",
                    "identifiers": cves,
                    "provenance": provenance(row, "/aliases", "never-merge-cves"),
                }
            )

        def descriptions(
            values: Any, path: str, row: dict[str, Any] = row, scalar: bool = False
        ) -> None:
            for i, value in enumerate(values if isinstance(values, list) else []):
                if isinstance(value, dict) and isinstance(value.get("value"), str):
                    out["descriptions"].append(
                        {
                            "lang": value.get("lang", "und"),
                            "value": value["value"],
                            "provenance": provenance(
                                row,
                                path if scalar else f"{path}/{i}",
                                "cna-before-supplemental-descriptions",
                            ),
                        }
                    )

        def references(values: Any, path: str, row: dict[str, Any] = row) -> None:
            for i, value in enumerate(values if isinstance(values, list) else []):
                if isinstance(value, dict):
                    out["references"].append(
                        {
                            "value": value,
                            "provenance": provenance(row, f"{path}/{i}", "retain-source-reference"),
                        }
                    )

        def evidence(
            value: Any,
            pointer: str,
            kind: str,
            row: dict[str, Any] = row,
            raw: dict[str, Any] = raw,
            ambiguous: bool = ambiguous,
        ) -> None:
            out["affected"].append(
                {
                    "kind": kind,
                    "value": value,
                    "association": "multi_cve_advisory" if ambiguous else "explicit",
                    "matching_usable": not ambiguous and not bool(raw.get("withdrawn")),
                    "comparison": "deferred_to_phase17",
                    "provenance": provenance(row, pointer, "preserve-native-version-semantics"),
                }
            )

        if source == "cve_list":
            meta = raw.get("cveMetadata", {})
            status = meta.get("state")
            out["lifecycle"] = {
                "value": {"PUBLISHED": "published", "REJECTED": "rejected"}.get(status, "unknown"),
                "provenance": provenance(row, "/cveMetadata/state", "official-cve-status-only"),
            }
            for key in ("datePublished", "dateUpdated", "dateReserved"):
                if meta.get(key):
                    out["dates"].append(
                        {
                            "kind": key,
                            "value": meta[key],
                            "preferred": True,
                            "provenance": provenance(
                                row, "/cveMetadata/" + key, "official-cve-dates"
                            ),
                        }
                    )
            containers = raw.get("containers", {})
            for container, path in [
                (containers.get("cna", {}), "/containers/cna"),
                *[(v, f"/containers/adp/{i}") for i, v in enumerate(containers.get("adp", []))],
            ]:
                descriptions(container.get("descriptions", []), path + "/descriptions")
                references(container.get("references", []), path + "/references")
                for i, weakness in enumerate(container.get("problemTypes", [])):
                    out["weaknesses"].append(
                        {
                            "value": weakness,
                            "provenance": provenance(
                                row, f"{path}/problemTypes/{i}", "retain-source-cwe"
                            ),
                        }
                    )
                for i, affected in enumerate(container.get("affected", [])):
                    evidence(affected, f"{path}/affected/{i}", "cna_product")
                for i, item in enumerate(container.get("metrics", [])):
                    for key, val in item.items():
                        if key.startswith("cvss") and isinstance(val, dict):
                            out["cvss"].append(
                                metric(
                                    val,
                                    row,
                                    f"{path}/metrics/{i}/{key}",
                                    container.get("providerMetadata", {}).get("orgId", ""),
                                )
                            )
        elif source == "nvd":
            descriptions(raw.get("descriptions", []), "/descriptions")
            references(raw.get("references", []), "/references")
            for field in ("published", "lastModified"):
                if raw.get(field):
                    out["dates"].append(
                        {
                            "kind": field,
                            "value": raw[field],
                            "preferred": False,
                            "provenance": provenance(row, "/" + field, "supplemental-source-date"),
                        }
                    )
            for i, value in enumerate(raw.get("weaknesses", [])):
                out["weaknesses"].append(
                    {
                        "value": value,
                        "provenance": provenance(row, f"/weaknesses/{i}", "retain-source-cwe"),
                    }
                )
            if "configurations" in raw:
                evidence(raw["configurations"], "/configurations", "nvd_configuration_logic")
            for key, values in raw.get("metrics", {}).items():
                for i, value in enumerate(values):
                    out["cvss"].append(
                        metric(
                            value.get("cvssData", {}),
                            row,
                            f"/metrics/{key}/{i}/cvssData",
                            value.get("source", ""),
                        )
                    )
            if raw.get("vulnStatus") == "Rejected" and out["lifecycle"]["value"] != "rejected":
                out["conflicts"].append(
                    {
                        "kind": "source_status",
                        "provenance": provenance(row, "/vulnStatus", "official-cve-status-wins"),
                    }
                )
            if out["lifecycle"]["value"] == "rejected" and raw.get("vulnStatus") != "Rejected":
                out["conflicts"].append(
                    {
                        "kind": "source_status",
                        "provenance": provenance(row, "/vulnStatus", "official-rejection-wins"),
                    }
                )
        elif source == "ubuntu":
            for key in ("packages", "release_packages", "releases"):
                if key in raw:
                    evidence(raw[key], "/" + key, "ubuntu_" + key)
            references(raw.get("references", []), "/references")
            for key in ("description", "summary", "title"):
                if isinstance(raw.get(key), str):
                    descriptions([{"lang": "en", "value": raw[key]}], "/" + key, scalar=True)
        elif source == "osv":
            for i, value in enumerate(raw.get("affected", [])):
                evidence(value, f"/affected/{i}", "osv_package")
            for key in ("summary", "details"):
                if isinstance(raw.get(key), str):
                    descriptions([{"lang": "en", "value": raw[key]}], "/" + key, scalar=True)
            references(raw.get("references", []), "/references")
            if raw.get("withdrawn"):
                out["conflicts"].append(
                    {
                        "kind": "withdrawn_advisory",
                        "provenance": provenance(
                            row, "/withdrawn", "withdrawn-evidence-not-active"
                        ),
                    }
                )
                if not CVE.fullmatch(identity):
                    out["lifecycle"] = {
                        "value": "withdrawn",
                        "provenance": provenance(row, "/withdrawn", "advisory-lifecycle"),
                    }
            for i, value in enumerate(raw.get("severity", [])):
                kind = value.get("type")
                version = {"CVSS_V2": "2.0", "CVSS_V3": "3.1", "CVSS_V4": "4.0"}.get(
                    kind, "unknown"
                )
                vector = value.get("score", "")
                if kind == "CVSS_V3" and str(vector).startswith("CVSS:3.0/"):
                    version = "3.0"
                out["cvss"].append(
                    metric(
                        {"version": version, "vectorString": vector}, row, f"/severity/{i}", "OSV"
                    )
                )
    valid = [(i, m) for i, m in enumerate(out["cvss"]) if m["validation_status"] == "valid"]
    if valid:
        preferred = min(
            valid,
            key=lambda item: (
                {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}[item[1]["cvss_version"]],
                RANK[item[1]["provenance"]["source_id"]],
                str(item[1]["metric_provider"]),
                str(item[1]["vector_string"]),
            ),
        )
        out["cvss"][preferred[0]]["is_preferred"] = True
    for version in ("2.0", "3.0", "3.1", "4.0"):
        comparable = [(i, m) for i, m in valid if m["cvss_version"] == version]
        if len({canonical(m.get("base_score")) for _, m in comparable}) > 1:
            out["conflicts"].append(
                {
                    "kind": "cvss_disagreement",
                    "version": version,
                    "assessments": [i for i, _ in comparable],
                }
            )
    languages = {d["lang"] for d in out["descriptions"]}
    for lang in sorted(languages):
        descriptions_in_language = [
            (i, d) for i, d in enumerate(out["descriptions"]) if d["lang"] == lang
        ]
        if len({d["value"] for _, d in descriptions_in_language}) > 1:
            out["conflicts"].append(
                {
                    "kind": "description_disagreement",
                    "lang": lang,
                    "assessments": [i for i, _ in descriptions_in_language],
                }
            )
    primary = [
        d
        for d in out["descriptions"]
        if d["provenance"]["source_id"] == "cve_list"
        and d["provenance"]["json_pointer"].startswith("/containers/cna/")
    ]
    primary = primary or out["descriptions"]
    out["primary_description"] = next(
        (d for d in primary if d["lang"] == "en"), next(iter(primary), None)
    )
    if out["lifecycle"]["value"] == "rejected":
        for item in out["affected"]:
            item["matching_usable"] = False
    out["quality"] = (
        "conflicted"
        if out["conflicts"]
        else "partial"
        if out["lifecycle"]["value"] == "unknown"
        or any(m["validation_status"] != "valid" for m in out["cvss"])
        else "complete"
    )
    return out
