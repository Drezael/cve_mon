# Phase 15 – Übergabe an Phase 16

Eingaben für Enrichment: cve.current_source_records, source_revisions, source_artifacts,
source_observations, revisionseigene source_record_identifiers und erfolgreiche source_streams.
Quelle+externe ID ist stabil; Aliase dürfen mehrere CVEs oder keine CVE referenzieren.
JSONB enthält die vollständigen semantischen Quelldaten. Inhalts- und Wire-SHA unterscheiden.

Events cve.source.new/changed/withdrawn/removed/completed/partial/failed sind Version 1,
Quelle cve-importer, ausschließlich feste Metadaten. Neue Jobs heißen cve.import.<source>,
Payload allein run_id. Dispatcherziele sind weiterhin explizit freizugeben; hier wird kein
Enricher-/Matching-/Finding-Workflow ausgelöst. Current-Rohrevision ist keine konsolidierte CVE.

NVD kann naive UTC-Zeitstempel liefern; nur dessen Formatprüfung berücksichtigt diese
Quellkonvention. Ubuntu liefert keine modifizierten-seit-Filter. CVEProject-Tageslücken
verlangen kontrolliertes Reconcile. OSV-Ökosysteme bleiben Betreiberkonfiguration.
Nachfolgende Phasen müssen Quellunterschiede, Rejected/Withdrawn, Katalogmitgliedschaft,
mehrdeutige Aliase und Originalpaketversionen erhalten und explizite Regeln ergänzen.

Tests: make cve-importer-check / cve-importer-integration / cve-importer-security /
cve-importer-concurrency / cve-importer-performance / cve-importer-e2e. Betrieb und
Recovery siehe docs/operations/cve-import*.md. Remote-CI wurde lokal nicht ausgelöst.

Lange Erstimporte lassen sich nach erschöpftem Jobbudget ausdrücklich mit
`resume --run-id <UUID>` fortsetzen, solange die Quelllease zum Run gehört. Der
Phase-7-Replay erhält Checkpoints und Quelldaten; kein automatisches Endlosbudget.
