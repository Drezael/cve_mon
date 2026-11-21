# ADR-0029: Getrennte Uploadwege und persistente Inventarannahme

Status: accepted. Datum: 07.11.2026.

Phase 11 konkretisiert ADR-0010/0011/0012/0013 und die geplanten Phase-0-Verträge.
Das Inventarformat 1.0 bleibt bytegleich. Technischer Zugang erfordert gleichzeitig
mTLS, die private Ingress-Capability und einen server-/zertifikats-/clientgebundenen
opaque Bearer mit festem inventory:submit. Dashboard-Dateien erfordern vollständige
Session/MFA, Origin/CSRF, menschliches Uploadrecht und explizite Server-ACL, auch für
Administratoren. Die Identitäten sind nicht austauschbar.

Beide Wege verwenden denselben begrenzten Validator und dieselbe Annahmespeicherung.
Originalbytes, JSON, Original-SHA-256, kanonischer Vergleichshash und geprüfte Provenienz
bleiben unveränderlich. Nur strukturelle administrative Feldnamen werden zurückgewiesen;
normale Inventarwerte wie Paketnamen bleiben zulässig. Parser laufen als kurzlebige
Prozesse mit harten CPU-/Adressraumgrenzen und überwachten Zeitlimits.

Die Phase-0-Planung verband UploadReceipt unmittelbar mit Snapshot/Job und sah 200 für
Duplikate vor. Phase 11 fordert persistente Annahme vor Phase 14. Neue versionierte
0.11-Verträge liefern deshalb nach erfolgreichem Commit immer 202/accepted, auch beim
idempotenten Retry. Sie enthalten keine Snapshot-/Job-ID. Alte Planungsverträge bleiben
als historische Quelle erhalten; für die implementierten Uploadwege gelten die neuen
Verträge. Sofortige Verarbeitung oder ein Platzhalterjob wären sachlich falsch.

Idempotenz ist an Kanal, geprüfte Identität, Server und Schlüssel gebunden. Gleicher
kanonischer Inhalt liefert dieselbe eigene Submission; widersprechender Inhalt 409.
Die globale inventory_id bindet Server und kanonischen Inhalt über beide Kanäle.
Unterschiedliche Herkunft erhält eigene Annahmeprovenienz, ohne fremde Receipt-IDs
preiszugeben. Phase 14 muss daraus fachlich höchstens einen Snapshot erzeugen.

Revision 00017 ist additiv. Native Trigger, private Quotas und feste Security-Funktionen
schützen Inhalt und Commitgrenzen. G909001 wird zur gemeinsamen Widerrufs-/ACL-Sperre
wiederverwendet; Schlüssel-/Quotasperren begrenzen Konkurrenz. api_ingest und api_security
erhalten nur Annahme-INSERT und Metadaten-SELECT, keine Payload-Leserechte oder
administrativen Gruppenrechte. Ein neuer Broker, Dateispeicherdienst oder Prozessor
ist nicht erforderlich. Das beschränkt Schreibparallelität bewusst; Phase 23 vermisst
höhere Last. Quotas zählen Originalbytes, keine garantierte physische Datenträgergröße.

[Architektur](../inventory-upload.md), [Lifecycle](../inventory-submission-lifecycle.md),
[Betrieb](../../operations/inventory-upload.md), [Übergabe](../../development/phase-11-handover.md).
