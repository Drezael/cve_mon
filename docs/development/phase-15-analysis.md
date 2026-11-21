# Phase 15 – Bestandsanalyse

Ausgang: Phase 14 abgeschlossen; API 0.11.1, Inventory 0.14.0,
cve-common/Dispatcher 0.7.0; Datenbankhead 00019. Sieben eigene Dienste und vier fremde
Nextcloudcontainer. Kein ausgeführter Quellenimport, keine automatische Quellplanung.
`/tmp/cve-phase15-before.json` und Containerbaseline erfassen den Ausgangsstand.

Wiederverwendet: Quellenregister aus 0004, Rollen/SSL/RLS, 00013-Jobruntime mit Leases,
ExecutionContext/Fencing, Outbox, gemeinsame DB-/HTTP-/Logging-/Healthbasis, Envoy/
Namespacefilter und die vorhandenen Backup-/Restorewerkzeuge. Die alten CVE-Tabellen
sind CVE-ID-gebunden; für eigenständige Advisories ist ein ergänzendes Quellenmodell notwendig.

Die Migration bleibt additiv; gezielte Rechteänderungen sperren Legacy-CVE-Schreibzugriff
für importer und Importcursor-Schreibzugriff für enricher. Die API erhält ausschließlich
Schema-USAGE und den kontrollierten Schedule-Funktionszugriff. Administrative Rollen und
Inventarverarbeitung bleiben getrennt. Kein externes Ansible-Repository wurde geändert.
