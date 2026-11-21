# Analyse Phase 17

Ausgangsstand: Phase 16, DB-Head 00022, neun laufende Dienste. Matcher war nur Vorbereitung.
Das Legacy-Matching referenziert cve.records/cve.revisions; die aktuelle fachliche Basis
liegt dagegen in cve.enrichment_revisions und immutable Inventory-Processor-Snapshots.
Deshalb neue Ergebnisrevisionen mit expliziter Source-Bindung, bestehende Runs weiterverwenden.

Phase-14-Versionen bleiben vollständig. Current-Snapshot-Pointer und Serverstatus müssen
bei jeder Publikation geprüft werden. Enrichment current_version ist ein Publikationszähler;
Revision-UUIDs dürfen nach A→B→A wieder aktuell sein. EPSS-Risikoupdates lösen keine technische
Versionsbewertung aus. NVD-AND und vulnerable=false sind keine unabhängigen Positivmatches.

Fehlende Voraussetzungen: verifizierte Ubuntu-OVAL-Evidenz, vollständige verifizierte CPE-
Inventarzuordnung, Commitgraph für OSV-GIT, Container-SBOM. Diese führen zu dokumentierter
Unsicherheit und werden nicht durch zusätzliche externe Imports oder Produktvermutungen ersetzt.
Die dauerhafte Vorheraufnahme unter .runtime/test-reports/phase-17-before.json schützt
bestehende Code-Dateien, beide Datenbanken und Envoy-/SMTP-Bindungen.
