# Matching Engine, Phase 17

cve-matcher 0.17.0 verarbeitet ausschließlich persistierte, verarbeitete Snapshots aus
inventory.matching_snapshots und unveränderliche cve.enrichment_revisions. PostgreSQL,
cve_common 0.7.0 und die Phase-7-Worker bleiben die Grundlage. Kein weiterer Broker.

Die Migration 00023 verwendet matching.runs weiter. Die alten matching.results samt
Finding-Fremdschlüsseln bleiben erhalten, verlieren aber das Matcher-INSERT-Recht.
Neue Resultate referenzieren über zusammengesetzte FKs das tatsächliche Snapshot-/Server-
und Enrichment-/CVE-Paar. Eine spätere Phase muss Finding-Verweise bewusst migrieren.

Pipeline: Outbox-Trigger → registrierter Job → strukturierte Suchschlüssel → Kandidat →
Identität → Versionsadapter → Quellregeln → Konflikte → Komponenten → Aggregat → Revision →
kontrollierte Publikation. Snapshot- und CVE-Auslöser verwenden dieselben Indizes. Frühere
Ergebnisse werden auch bei verschwundenen Komponenten oder entfernten Source-Identitäten
neu geprüft. Ein fehlender Kandidat ist keine Entwarnung; nicht zuordenbare Aussagen
werden separat gezählt. Reconciliation erfolgt ausdrücklich per Operatorauftrag.

Ein kurzer globaler Index-Lock serialisiert die Veröffentlichung beider Suchrichtungen:
Gleichzeitige neue Inventar- und CVE-Schlüssel dürfen sich nicht gegenseitig übersehen.
Fachbewertungen verwenden einen separaten Lock pro Eingabe-Fingerprint und laufen parallel.
Die Input-IDs bleiben in Childjobs fixiert. Atomarer Fachcommit und Jobabschluss prüfen
den Lease-Fence; abgebrochene Commits erzeugen keine halben Ergebnisse.

matching.publish sperrt den aktiven Server sowie beide autoritativen Pointer. Veraltete
Eingaben bleiben historisch, können den Current-Pointer aber nicht ersetzen. Der monotone
Publikationszähler behandelt auch A→B→A. matching.current_evaluations.is_current zeigt
zwischen Eingabeänderung und Neubewertung ausdrücklich die veraltete Grundlage an.

Die Implementierung bleibt in wenigen fachlich gegliederten Modulen statt leerer
Verzeichnisgerüste: contracts, versions, ranges, cpe, engine, service, main und files.

Affected-Belege werden als Provenienz, Enrichment-JSON-Pointer und SHA-256 der unveränderlichen Aussage referenziert. Dadurch bleiben Originalbaum und Vergleichsgrenzen vollständig prüfbar, ohne denselben großen Quellausdruck je Installation zu duplizieren. Der tatsächlich verglichene Operand steht separat neben der unveränderten Installationsversion.
