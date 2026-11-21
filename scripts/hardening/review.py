"""Minimized, deduplicated finding register; classification never grants an exception."""

import html
import json
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from scripts.hardening.supply_chain import REPORTS, ROOT


def cell(value: object) -> str:
    return html.escape(str(value)).replace("|", "\\|").replace("\n", " ")


def generate() -> dict[str, Any]:
    gate = json.loads((REPORTS / "image-gate.json").read_text())
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for file in sorted(REPORTS.glob("cve-*-vulnerabilities.json")):
        service = file.name.removesuffix("-vulnerabilities.json")
        report = json.loads(file.read_text())
        for result in report["Results"]:
            for item in result.get("Vulnerabilities", []):
                if item["Severity"] not in {"HIGH", "CRITICAL", "UNKNOWN"}:
                    continue
                identity = (
                    item["VulnerabilityID"],
                    item["PkgName"],
                    item["InstalledVersion"],
                    result["Type"],
                )
                if item.get("FixedVersion"):
                    action = (
                        "geprüfte Produkt-/Komponentenaktualisierung erforderlich; "
                        "neueste Produktversion bedeutet nicht automatisch Komponentenfix"
                    )
                else:
                    action = (
                        "kein Distributionsfix im Report; Herstellerpatch oder belegte "
                        "Nichtbetroffenheit/ausdrücklich genehmigte Kompensation erforderlich"
                    )
                row = grouped.setdefault(
                    identity,
                    {
                        "id": item["VulnerabilityID"],
                        "package": item["PkgName"],
                        "installed": item["InstalledVersion"],
                        "type": result["Type"],
                        "severity": item["Severity"],
                        "fixed": item.get("FixedVersion", ""),
                        "vendor_status": item.get("Status", "unknown"),
                        "services": [],
                        "assessment": "bekannte installierte Komponente; Plattformausnutzbarkeit "
                        "nicht als widerlegt behandelt; bleibt Freigabeblocker",
                        "action": action,
                        "accepted": False,
                    },
                )
                row["services"].append(service)
    rows = sorted(
        grouped.values(),
        key=lambda v: (
            {"CRITICAL": 0, "HIGH": 1, "UNKNOWN": 2}[v["severity"]],
            v["package"],
            v["id"],
        ),
    )
    for row in rows:
        row["services"] = sorted(set(row["services"]))
    secrets = [v for v in gate["blocking_findings"] if v["package"] == "embedded-secret"]
    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "scanner": gate["scanner"],
        "artifact_occurrences": len(gate["blocking_findings"]),
        "unique_package_version_advisory_findings": len(rows),
        "severity_occurrences": dict(Counter(v["severity"] for v in gate["blocking_findings"])),
        "exceptions_accepted": 0,
        "production_gate": "NO_GO" if gate["blocking_findings"] else "NO_BLOCKING_IMAGE_FINDINGS",
        "findings": rows,
        "embedded_material_findings": secrets,
        "embedded_material_review": (
            "offener Materialbefund; Herkunftsprüfung erforderlich, keine automatische Ausnahme"
            if secrets
            else "kein eingebettetes Schlüsselmaterial vom Scanner gemeldet"
        ),
    }
    target = ROOT / ".runtime/test-reports/phase-23-findings-review.json"
    target.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    target.chmod(0o600)
    lines = [
        "# Imagebefunde Phase 23",
        "",
        "Stand: " + summary["generated_at"],
        "",
        f"{summary['artifact_occurrences']} blockierende Fundstellen über13 Artefakte; "
        f"{len(rows)} eindeutige Kombinationen aus Paketversion, Advisory und Ökosystem. "
        "Gemeinsam verwendete Basisbibliotheken erzeugen Mehrfachmeldungen. "
        "Scannerschwere ist keine bestätigte Ausnutzbarkeit der Anwendung.",
        "",
        (
            "Alle Einträge sind als offene Update-/Nachweisentscheidung bewertet. "
            if rows or secrets
            else "Es bestehen keine blockierenden Imagebefunde. "
        )
        + "Es wurde keine Ausnahme oder Risikoakzeptanz erteilt. Fehlende Fixversionen "
        "werden nicht als Entwarnung behandelt. Nicht kompatibel geprüfte Majorupdates "
        "einzelner n8n-Transitivpakete werden nicht ungeprüft in das Produkt eingesetzt.",
        "",
        "| Schwere | Advisory | Paket / installiert | Fix laut Scanner | Dienste | Maßnahme |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                cell(v)
                for v in [
                    row["severity"],
                    row["id"],
                    row["package"] + " / " + row["installed"],
                    row["fixed"] or "kein gemeldeter Distributionsfix",
                    ", ".join(row["services"]),
                    row["action"],
                ]
            )
            + " |"
        )
    lines += [
        "",
        "Zusätzlicher Materialbefund: " + summary["embedded_material_review"],
        "",
        "Rohreports, CycloneDX-SBOMs, Image-/Configdigests und Inputhashes stehen unter "
        ".runtime/test-reports/phase-23-supply-chain. Secret-Matches und Codeauszüge werden "
        "vor Veröffentlichung entfernt. Bewertungsverantwortung: Plattformbetreiber / "
        "Sicherheitsverantwortlicher. Hohe/kritische Befunde sind vor Produktionsfreigabe "
        "zu schließen oder anhand konkreter Nachweise ausdrücklich zu genehmigen.",
    ]
    (ROOT / "docs/security/phase-23-image-findings.md").write_text("\n".join(lines) + "\n")
    return summary


if __name__ == "__main__":
    value = generate()
    print(
        json.dumps(
            {
                k: v
                for k, v in value.items()
                if k not in {"findings", "embedded_material_findings", "embedded_material_review"}
            }
        )
    )
