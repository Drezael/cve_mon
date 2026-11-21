# Phase-13-Abnahme

Stand: 07.11.2026. **completed — alle 45 Aufträge, 138 Pflichtprüfungen,
75 SUB-Invarianten und 65 Schlusskriterien lokal nachgewiesen.**

879 verschiedene Tests bestanden: 103 neue Submitprüfungen, 116 Collect-, 73 bestehende
Launcher-, 509 CVE-Standard- und 78 vollständige Uploadtests. Darin 13 neue native E2E-
Szenarien gegen die tatsächliche isolierte Phase-11-Instanz. Andere unveränderte Backend-
Docker-Suiten wurden in dieser Phase nicht erneut ausgeführt und sind nicht mitgezählt.

Umsetzung im vorhandenen /home/gerald/Documents/GitHub/ansible. Vollständige Auftragsliste,
Einzelabnahme und Betriebsdokumentation unter docs/inventory_submit/ dieser Arbeitskopie.
Controllerseitiger Submit über unveränderte Exportbytes, bestehenden Launcher/Vaults,
servergebundene Tokens und mTLS. Sichere temporäre Kopien, begrenzte Retries, atomare lokale
Receipts, autorisierter Status und explizit isolierter Batch. Keine Zielserververbindung.

Die bestehende APIantwort verwendet server_id, kein neuer Alias server_uuid. Status ohne
Payload-Hash erzeugt keinen neuen Receipt. Nur bestätigter POST kann fehlenden lokalen
Nachweis reparieren. 202 bedeutet ausschließlich accepted, keine fertige Fachverarbeitung.
Token-/Zertifikatsrotation, Widerruf, verlorene Antworten, API-Neustart, SIGTERM, lokale
Receiptfehler, parallele Prozesse und zuerst fehlgeschlagener Batchrequest geprüft.

make check, Ruff/Format, Mypy (288 Dateien), Syntax-/YAML-/Schema-/Secretprüfungen erfolgreich.
Bestehende Vaults, Schlüssel, Host-Specs und Verschlüsselungsverfahren unverändert; nur
Submit-lokaler ANSIBLE_LOCAL_TEMP-Pfad im vorhandenen Executor ergänzt. Kein Schema-/API-/
Datenbankupdate: API 0.11.1, Revision 00018. Sechs eigene Dienste healthy, fremde Nextcloud-
Container mit bisherigen IDs und keine Testfachdaten im normalen Entwicklungsdeployment.

CI vorbereitet, nicht remote ausgeführt; native CVE-CI benötigt passende Ansible-Revision
über ANSIBLE_SUBMIT_REF. Produktive Config und technische Credentials bleiben ausdrücklich
Operatoraufgabe. Keine Commits/Pushes oder automatische Phase 14.
[Übergabe](phase-13-handover.md), [ADR-0031](../architecture/decisions/ADR-0031-ansible-submit-phase13.md),
[Dateimanifest](phase-13-files.json).
