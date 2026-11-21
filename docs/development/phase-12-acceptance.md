# Phase-12-Abnahme

Stand: 07.11.2026. **completed — alle 45 Aufträge, 105 Pflichtprüfungen,
60 COL-Invarianten und 60 Schlusskriterien lokal nachgewiesen.**

1291 verschiedene Tests bestanden: 189 Ansible-Prüfungen (99 Unit/Sicherheit/CLI,
17 reale Integration, 73 vorhandene Launcher-Tests) sowie 1102 CVE-Tests einschließlich
vollständiger Regression. make check, native YAML-/Ansible-Syntaxchecks, Ruff/Format,
Secretprüfungen, neue Migration, Offline-Wheelinstallation und installierte Schemaressourcen
geprüft. Remote-CI vorbereitet, nicht ausgeführt.

Die Umsetzung liegt im vorhandenen /home/gerald/Documents/GitHub/ansible. Vollständige
Auftragsliste und Einzelabnahme: docs/inventory/phase-12-status.md und
phase-12-acceptance.md in dieser Arbeitskopie. Hauptplaybook server.inventory.collect,
ausschließlich lesende ansible.builtin-Erfassung über unveränderten Launcher/Vault/SSH/sudo.
Keine neue Rolle/Collection. Atomare lokale Ausgabe mit 0700/0600, keine Überschreibung,
keine Symlinks, kein automatischer Upload. Bestehende lokale Hoständerung erhalten.

Ubuntu 24.04, Debian 13, Fedora 43 über echten Launcher/SSH/sudo geprüft. Fedora im Container
korrekt partial wegen fehlendem laufenden Service-Manager; Betriebssystem und RPM-Pakete
vollständig. Mehrhost-, Parallel-, Wiederholungs-, SSH-/sudo-/IO-Fehler und echte lokale
Docker-Leseabfragen nachgewiesen. Keine verwalteten produktiven Zielserver für Tests verändert.

Gemeinsamer Vertrag 1.1 für vollständige Phase-12-Daten; 1.0 bytegleich erhalten. API 0.11.1
und additive Revision 00018 aktiv, beide Uploadwege kompatibel. Keine zusätzlichen Dienste,
Ports oder Privilegien. Sechs eigene Dienste healthy, vier fremde Nextcloud-Container mit
unveränderten IDs. Keine Testfachdaten im normalen Entwicklungsdeployment.

Ein früher zeitabhängiger Dispatcher-Test wurde in der unveränderten vollständigen Suite
erfolgreich wiederholt. Finale erfolgreiche Protokolle unter .runtime/test-reports/phase-12-*.
Keine Commits oder Pushes. Phase 13 bleibt Folgearbeit.
[Übergabe](phase-12-handover.md), [ADR-0030](../architecture/decisions/ADR-0030-inventory-collection-phase12.md),
[Dateimanifest](phase-12-files.json).
