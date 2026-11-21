# Übergabe Phase 14

Der vorgesehene Dienst cve-inventory 0.14.0 verarbeitet angenommene 1.0-/1.1-Submissions
über den registrierten Phase-7-Handler inventory.process_submission. Revision 00019 ergänzt
Jobbereitstellung/Backfill, Verarbeitungsreferenzen, versiegelte Snapshots, Kernel/Images,
Current-Pointer und Metadatenviews. Bestehende Annahme-Receipts bleiben unverändert.

Phase 15 darf CVE-Daten unabhängig importieren. Phase 17 erhält stabile snapshot_id,
server_id, Erfassungszeit, Normalisierungsversion, Qualität und is_current über
inventory.matching_snapshots sowie registrierte inventory.current_changed-Ereignisse.
Der Ereignispayloadvertrag liegt unter contracts/events/inventory-processing-v1.schema.json.
Folgeverarbeitung kann idempotent die Snapshot-ID referenzieren. Outbox-Zustellungen
können verzögert oder wiederholt eintreffen. Phase 17 muss den aktuellen Pointer und
den administrativen Serverstatus bei Verarbeitung erneut prüfen; ein historisches
current_changed-Ereignis beweist nicht, dass der Snapshot weiterhin aktuell ist. Noch keine Matchingjobs,
Findings oder n8n-Workflows. Auslieferungsziele bleiben ausdrücklich geschlossen.

Paketversionen sind vollständig in inventory.packages.version erhalten. Epoch, Upstream,
Release, Architektur, Quellpaket und Originaldaten stehen getrennt zur Verfügung.
unknown/invalid_version und unbekannte Distributionen sind keine Verwundbarkeitsaussage.
Die Matching Engine muss distributionsspezifische Backports berücksichtigen; fehlende oder
partielle Erfassung ist kein Sicherheitsnachweis. Installierte Kernelpakete sind nicht der
Nachweis des laufenden Kernels. Image-Tags beweisen keine Softwareversion.

Current-Pointer und Historie sind technisch getrennt von administrativen Serverdaten.
Archivierte Server können historische Ergebnisse haben; spätere Verbraucher müssen ihren
administrativen Status beachten. Keine automatische Retention. Fachliche Neuverarbeitung
bereits erfolgreicher Bestände benötigt einen neuen versionierten und auditierten Vertrag.
[Architektur](../architecture/inventory-processor.md), [Betrieb](../operations/inventory-processor.md),
[Abnahme](phase-14-acceptance.md).
