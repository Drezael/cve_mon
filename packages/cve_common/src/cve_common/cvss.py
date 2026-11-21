"""Validated CVSS assessments shared by native V5 reads and historical adapters."""

from decimal import Decimal, InvalidOperation
from typing import Any

from cvss import CVSS2, CVSS3, CVSS4  # type: ignore[import-untyped]


def provenance(row: dict[str, Any], pointer: str, rule: str) -> dict[str, Any]:
    return {
        "source_id": row["source_id"],
        "external_id": row["external_id"],
        "source_revision_id": str(row["revision_id"]),
        "json_pointer": pointer,
        "rule": rule,
        "rule_version": "enrichment-1",
    }


def metric(
    value: dict[str, Any], row: dict[str, Any], pointer: str, provider: str = ""
) -> dict[str, Any]:
    version = str(value.get("version", ""))
    vector = value.get("vectorString")
    score = value.get("baseScore")
    out = {
        "cvss_version": version,
        "vector_string": vector,
        "base_score": score,
        "severity": value.get("baseSeverity"),
        "metric_provider": provider,
        "source_assessment": value,
        "score_nomenclature": "CVSS-B",
        "validation_status": "incomplete",
        "is_preferred": False,
        "provenance": provenance(row, pointer, "cvss-validated-version-source-order"),
    }
    if version not in {"2.0", "3.0", "3.1", "4.0"}:
        out["validation_status"] = "unsupported_version"
        return out
    if not isinstance(vector, str) or len(vector) > 1024:
        return out
    tokens = vector.split("/")
    if len({v.split(":")[0] for v in tokens}) != len(tokens):
        out["validation_status"] = "invalid_vector"
        return out
    try:
        if version == "4.0":
            if not vector.startswith("CVSS:4.0/"):
                raise ValueError()
            parsed: Any = CVSS4(vector)
            supplied = Decimal(str(score)) if score is not None else None
            base_keys = {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
            base_tokens = [t for t in tokens[1:] if t.split(":")[0] in base_keys]
            base_vector = "CVSS:4.0/" + "/".join(base_tokens)
            calculated = Decimal(str(CVSS4(base_vector).scores()[0]))
            context_score = Decimal(str(parsed.scores()[0]))
            out["context_score"] = str(context_score)
            context_mismatch = False
            if value.get("threatScore") is not None:
                threat_tokens = [t for t in tokens[1:] if t.split(":")[0] in base_keys | {"E"}]
                expected_threat = Decimal(
                    str(CVSS4("CVSS:4.0/" + "/".join(threat_tokens)).scores()[0])
                )
                context_mismatch = Decimal(str(value["threatScore"])) != expected_threat
            if value.get("environmentalScore") is not None:
                context_mismatch = (
                    context_mismatch or Decimal(str(value["environmentalScore"])) != context_score
                )
            threat = any(t.startswith("E:") and t != "E:X" for t in tokens)
            environmental = any(
                t.split(":")[0]
                in {
                    "CR",
                    "IR",
                    "AR",
                    "MAV",
                    "MAC",
                    "MAT",
                    "MPR",
                    "MUI",
                    "MVC",
                    "MVI",
                    "MVA",
                    "MSC",
                    "MSI",
                    "MSA",
                }
                and not t.endswith(":X")
                for t in tokens
            )
            out["score_nomenclature"] = (
                "CVSS-B" + ("T" if threat else "") + ("E" if environmental else "")
            )
        else:
            context_mismatch = False
            if version != "2.0" and not vector.startswith("CVSS:" + version + "/"):
                raise ValueError()
            parsed = CVSS2(vector.removeprefix("CVSS:2.0/")) if version == "2.0" else CVSS3(vector)
            supplied = Decimal(str(score)) if score is not None else None
            calculated = Decimal(str(parsed.scores()[0]))
        if (
            context_mismatch
            or supplied is not None
            and (not supplied.is_finite() or not 0 <= supplied <= 10 or supplied != calculated)
        ):
            out["validation_status"] = "score_mismatch"
        else:
            out["validation_status"] = "valid"
            out["validated_score"] = str(calculated)
            if score is None:
                out["base_score"] = str(calculated)
            severity = (
                "NONE"
                if calculated == 0
                else "LOW"
                if calculated < 4
                else "MEDIUM"
                if calculated < 7
                else "HIGH"
                if calculated < 9
                else "CRITICAL"
            )
            if version == "2.0":
                severity = "LOW" if calculated < 4 else "MEDIUM" if calculated < 7 else "HIGH"
            out["calculated_severity"] = severity
    except (ValueError, TypeError, KeyError, InvalidOperation, ArithmeticError):
        out["validation_status"] = "invalid_vector"
    except Exception:
        out["validation_status"] = "invalid_vector"
    return out
