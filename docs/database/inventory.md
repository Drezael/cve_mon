# Inventare, Herkunft und Erfassungsqualität

`inventory.snapshots`: interner UUID-PK id, globale UNIQUE inventory_id, registrierter server_id,
schema_version, captured_at/received_at, collection_status complete/partial/failed,
content_sha256 (32 Bytes), original_json JSONB und original_bytes sowie Verarbeitungsstatus
pending/processing/processed/failed, processing_error_code und processed_at.
CHECKs binden Original-JSON an Originalbytes/SHA-256 sowie Server-/Inventaridentität und Metadaten.
Die Originalfelder sind nach INSERT unveränderlich; der Processor darf nur Verarbeitungsfelder
aktualisieren. Rekursive administrative Gruppen-/Sortier-/Stammdatenfelder werden abgewiesen.
Der vollständige JSON-Schema-/Duplikat-/Zukunftszeit- und Uploadautorisierungscheck folgt in Phase 11.

`upload_receipts` speichert source ansible_api/dashboard_file, snapshot_id, Zeit, request_id,
certificate_reference und jeweils genau passenden actor_user_id bzw. technical_principal_id.
Die API setzt diese vertrauenswürdigen Herkunftsfelder aus der authentifizierten Verbindung;
ein vom Client gesendetes Quelllabel reicht nicht. Der Technical-Principal ist kein Benutzerkonto.

`collection_sections` speichert je Snapshot os/packages/services/containers den Zustand
complete/partial/failed/not_collected und error_code. Fehlende Erfassung ist keine leere Liste.
Ein verarbeitetes complete-Inventar benötigt vollständige Kernbereiche os/packages/services;
Container bleiben gemäß Inventarvertrag optional. `operating_systems` enthält OS-/Kerneltexte,
`packages` unveränderte Version, Architektur, Paketmanager, optionale Quellpaket-/Quellversion
und software_identity; UNIQUE(snapshot_id,name,version,architecture,package_manager).
`services` und `containers` speichern beobachteten Zustand und originale Daten je Snapshot;
Containerdaten sind keine Live-Statuspage-Daten.

`current_snapshots` wählt den neuesten vollständig verarbeiteten kompletten Snapshot nach
captured_at und inventory_id. `effective_sections` wählt je Bereich den letzten vollständigen
Nachweis. `positive_partial_sections` stellt zusätzlich jüngere positive Teilbeobachtungen
bereit, ohne daraus eine vollständige Bestandsliste abzuleiten. failed/not_collected und verspätete
ältere Uploads überschreiben keine neuere vollständige Evidenz. Current/effective sind abgeleitete
Sichten statt zurücksetzbarer administrativer Zeiger. Historie bleibt vollständig erhalten.

Eine doppelte inventory_id wird durch UNIQUE erkannt. Phase 11 vergleicht beim Konflikt unter
Transaktion Identität und Hash: gleicher Inhalt idempotent, veränderter Inhalt Konflikt;
keine automatische ON-CONFLICT-Überschreibung. Snapshot, Receipt, Job und Outbox werden gemeinsam
committed. Normalisierte Daten und vollständige Erfassungsqualität in einer Processortransaktion
speichern. Paketversionen einschließlich Epoch/Revision bleiben text, kein numerisches Kürzen.

Indizes: server_id/captured_at/inventory_id, partieller aktueller Snapshotindex,
Paketname/Paketmanager/Architektur. Keine automatischen Gruppen- oder Reihenfolgeänderungen.

## Umsetzung Phase 14

Revision 00019 verwendet die vorhandenen Snapshot-/Bestandstabellen weiter und ergänzt
native Versiegelung, Kernel/Images, Verarbeitungsreferenzen, Current-Pointer und Metadatenviews.
Maßgeblich für die Verarbeitung sind [Snapshotmodell](inventory-snapshots.md) und
[aktuelle Auswahl](inventory-current-selection.md). Die ursprünglichen Annahmedaten bleiben
unveränderlich und 202/accepted bestätigt weiterhin ausschließlich die dauerhafte Annahme.
