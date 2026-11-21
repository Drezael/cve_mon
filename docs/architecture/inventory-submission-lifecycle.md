# Annahmedaten und spätere Verarbeitung

Revision 00017 ergänzt inventory.submissions, weil die vorhandenen upload_receipts eine
Snapshot-FK besitzen und Phase 11 noch keine fachlichen Snapshots erzeugen darf. Original-
JSONB, Originalbytes, SHA-256, kanonischer SHA-256, Inventar-/Server-UUID, Schema, Erfassungs-/
Empfangszeit, Korrelation und geprüfte Provenienz bleiben append-only. status ist ausschließlich
accepted; kein Runtime-UPDATE/DELETE, keine Scheinverarbeitung. Sessionreferenzen sind UUIDs
ohne FK zur kurzlebigen Session, damit spätere Sessionbereinigung keine Historie blockiert.

Idempotenz: source + geprüfte Identität + Server + Schlüssel. Ohne Header dient inventory_id
als Schlüssel. Kanonisierung v1: sortierte Objektkeys, kompakte UTF-8-Repräsentation, keine
Unicode-Normalisierung, Arrayreihenfolge unverändert. Gleicher Schlüssel/kanonischer Inhalt
liefert dieselbe Submission; anderer Inhalt 409. Originalbytes/Originalhash bleiben die der
ersten Annahme. Eine globale unveränderliche Identitätsregistry verhindert, dass inventory_id
auf anderen Server oder anderen Inhalt umgebunden wird.

Andere Identität oder anderer Uploadweg erzeugt einen eigenen Annahmedatensatz mit eigener
Provenienz und tatsächlichen Bytes; es wird keine fremde Submission-ID offengelegt. Originaler
Token/Client/Zertifikat beziehungsweise Benutzer/Session bleiben nachvollziehbar. Keine
Dateinamen oder vollständigen IP-Adressen im Annahmedatensatz. Status zeigt ausschließlich
Metadaten der eigenen Herkunft und aktuellen Serverberechtigung, niemals den Payload.

Phase 14 aktiviert den registrierten Handler und eine gesonderte Verarbeitungshistorie mit
Snapshotreferenz. submission_id ist Eingabe; fachliche Idempotenz richtet sich zusätzlich nach
der globalen inventory_id und dem kanonischen Hash, damit kanalübergreifende Receipts keinen
zweiten fachlichen Snapshot erzeugen. Originale und Herkunft werden nicht überschrieben.

Aktueller Betrieb: [Inventory Processor](inventory-processor.md),
[Snapshotmodell](../database/inventory-snapshots.md),
[Annahmekompatibilität](decisions/ADR-0032-inventory-processing-phase14.md).
