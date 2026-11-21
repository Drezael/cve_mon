# Übergabe an Phase 17

Aktuelle Fachdaten: cve.current_enrichment, immutable enrichment_revisions, enrichment_inputs
und kategorisierte enrichment_assertions. Jede Aussage trägt Quellenrevision/Pointer/Regel.
CVE und Advisory sind unterschiedliche Identitätsarten; Mehrfachaliase verschmelzen CVEs nicht.
Mehrdeutige oder zurückgezogene Evidenz darf nicht als uneingeschränkt aktiv verwendet werden.
Historische und aktuelle Revisionsidentität sind ausdrücklich zu unterscheiden.

Matching muss native Versionstypen, Ubuntu-Epoch/Release/Backports, OSV-Ökosystem-/Git-Ranges
und vollständige NVD-AND/OR/Negate-Logik berücksichtigen. Keine hier gespeicherte Evidenz ist
bereits eine Entscheidung über einen Inventarsnapshot. Fehlende Informationen bleiben unbekannt.
Die alten matching.results-FKs auf Legacy-CVE-Revisionen sind in Phase 17 bewusst an die
neuen Enrichment-Revisionen anzupassen; Phase 16 schreibt keine Matchingtabellen.

KEV: konkrete Katalogrevision, dynamisches kev_status (present/absent/unknown) und
kev_is_current prüfen. Die unveränderliche Revision beschreibt ihren historischen Katalog.
EPSS: separater vollständiger Tagesstand mit Modell, Datum, Alter und Stale-Kennzeichnung;
fehlend ist nicht 0. EPSS-Änderungen sind keine Änderung betroffener Paketversionen.
Events cve.enrichment.created/changed/rejected/aliases_changed/affected_changed/cvss_changed/
kev_changed/epss_updated enthalten nur Metadaten. Es sind keine Matchingrouten freigegeben.

Betrieb und Recovery: docs/operations/cve-enricher.md, cve-enrichment-recovery.md und epss-sync.md.
Keine automatische Vollneuberechnung beim Start. Regelversion enrichment-1 ist explizit;
neue Regeln benötigen eine geprüfte Version und kontrollierten Backfill.

Maschinenlesbarer Ergebnisvertrag: [Enrichment v1](../../contracts/cve/enrichment-v1.schema.json).
Die Current-View-Spalten für Revisions-ID, Publikationszähler und KEV-Gültigkeit sind
Metadaten zusätzlich zum unveränderlichen JSON-Ergebnis.

Outbox-Aggregate und Idempotenzschlüssel sind begrenzte stabile Hashes; die lesbare Identität
steht im Payload. current_version ist der monotone Publikationszähler, auch bei Rückkehr
zu einer bekannten Revision. Empfänger dürfen eine erneute Publikation nicht allein anhand
der bereits bekannten Revisions- oder Dataset-ID verwerfen.
