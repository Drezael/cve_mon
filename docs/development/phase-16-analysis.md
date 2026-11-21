# Phase 16 – Ausgangsstand

Phase 15 war abgeschlossen: API 0.11.1, Inventory 0.14.0, Importer 0.15.0,
cve-common/Dispatcher 0.7.0, Head 00020 und acht gesunde eigene Dienste. Vier fremde
Nextcloudcontainer bleiben erhalten. Quellenrecords, Revisionen, Aliase und Provenienz
sind vorhanden; n8n und Matcher sind keine Voraussetzungen der Enrichment-Verarbeitung.

Die Legacy-Enrichments hängen an CVE-ID-gebundenen Quellrevisionen und enthalten ein
pauschales CVSS/EPSS-Feld. Sie eignen sich nicht als vollständige quellenübergreifende,
Advisory-fähige Revision oder separate EPSS-Historie. Migration 00021 ergänzt daher
geeignete Strukturen, ohne Rohdaten oder bestehende Inventar-/Verwaltungsmodelle umzubauen.
Bestehende Jobs, Fencing, Outbox, TLS, Guardinstallation und Backup/Restore werden wiederverwendet.
Die vollständige Benutzeranweisung autorisiert alle 45 Aufträge; die Vorlage für einen
isolierten Analyseauftrag am Dokumentende begrenzt diesen Auftrag nicht.
