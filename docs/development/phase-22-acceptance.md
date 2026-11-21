# Phase-22-Abnahme

Phase 22 ist am 10.11.2026 vollständig abgeschlossen. Alle 45 Aufträge sind umgesetzt. Die [Testmatrix](../testing/phase-22-test-matrix.md) ordnet die 177 Pflichtkriterien Implementierung und Nachweisen zu.

Die integrierte Statusseite `/status` umfasst 16 Dienste und vier Pipelines, feste technische Prüfungen, fachliche Freshness-/Queue-/Worker-Signale, unveränderliche Messungen, Historie, Abhängigkeiten, Hysterese, Incidents und getrennte Wartungsfenster. Globale Übersicht, administrative Diagnose und Wartungsänderungen verwenden die bestehende Anmeldung und getrennte Berechtigungen. Wartung verwendet MFA, CSRF, Step-up, Objektversion und Audit. Kritische Statusereignisse nutzen die bestehende Phase-19-Alarmkette mit Deduplizierung und erneuter Empfängerprüfung.

## Validierung

- `make check`: Ruff und Formatierung für 908 Dateien, Mypy für 423 Quelldateien, 588 erfolgreiche Standardtests, Repository-/Konfigurationsprüfung und Secretprüfung erfolgreich. Die Secretbaseline blieb unverändert.
- Status: 37 Python-Unit-/Protokolltests, sieben native PostgreSQL-/API-Integrationstests und ein vollständiger Laufzeittest mit dem tatsächlichen Stack erfolgreich. Die nativen Fälle prüfen auch Konkurrenz, Retention, unveränderliche Messungen, alte Beobachtungen, Audit, Berechtigungen und Alarmverarbeitung.
- Frontend: Typecheck, Lint, Produktionsbuild und 29 Komponententests erfolgreich. Vier Status-Browsertests über tatsächliches TLS inklusive Anmeldung, Wartung, Rollen, Historie, API-Ausfall und Barrierefreiheit erfolgreich; responsive Screenshots bei 320, 768 und 1440 Pixeln.
- Regression: 82 Notification-, 146 Authentifizierungs-/Autorisierungs- und 51 Infrastrukturtests im jeweils letzten Ergebnis erfolgreich. Fünf native Dashboard-/Verwaltungsfälle mit insgesamt 13 bestehenden Browserfällen erfolgreich.
- Ausfälle und Wiederanlauf von n8n, Envoy, Postfix, PostgreSQL und API wurden im isolierten Laufzeitprojekt geprüft. Ebenso Zertifikatsfehler, veraltete Adapterdaten und fehlende Messwerte. Es wurde keine echte Mail versendet und kein Zielsystem über SSH oder Ansible angesprochen.
- Begrenzter Datenbanklastfall: 100 Beobachtungen in rund 402 ms persistiert, Historienabruf rund 19 ms. Responsive Browseransichten im geprüften lokalen Lauf etwa 0,9–1,1 Sekunden. Diese Messungen sind lokale Funktions-/Leistungsnachweise, keine Produktionskapazitätszusage.

Nachweise liegen unter `.runtime/test-reports/phase-22-*`: `check.log`, `unit.log`, `native.xml`, `runtime.xml`, `playwright.json`, `vitest.log`, `dashboard-regression.xml`, `regression-summary.json`, `outages.json`, `database-performance.json`, `browser-performance.json` und `live-verification.json`. Die Regressionszusammenfassung verwendet das letzte Ergebnis je Testkennung. Ursprüngliche Fehlerberichte bleiben erhalten; ihre Ursachen wurden in den Tests beziehungsweise exakten Infrastrukturannahmen korrigiert und die betroffenen Gruppen erneut erfolgreich ausgeführt.

## Aktivierung und Bestandsschutz

Vorheraufnahme und vollständiges Backup wurden unter `.runtime/test-reports/phase-22-before.json` und `.runtime/phase22-pre-migration` angelegt. Migration `00030_status_monitoring` ist aktiv, API und Notification laufen mit Version `0.22.0-phase22`. Alle 13 bestehenden Dienste sind gesund; kein weiterer Container wurde eingeführt.

Der Livevergleich bestätigt unveränderte bestehende Fach- und Sicherheitsdaten. Die ausdrücklich ergänzten Statusberechtigungen, Ereignistypen und Jobregistrierung wurden beim Hashvergleich normalisiert; auch die bisherigen Katalogzeilen sind unverändert. Laufende Job-/Ausführungsmetadaten wurden separat berücksichtigt. n8n-Workflows und verschlüsselte Credentials, Versand- und Egresspolicies sowie die vier fremden Nextcloud-Container sind unverändert. Die aktualisierten Netzwerkbindungen entsprechen den eigenen aktuellen Containern. Quellcode in API und Notification sowie aktivierte statische Assets entsprechen dem Repositorybuild. HTTPS, CSP, Cacheverhalten und Zugriffsschutz sind geprüft.

Beim erforderlichen Neustart fiel das bereits abgelaufene öffentliche Zertifikat der Entwicklungs-Upstream-CA auf. Es wurde mit demselben vorhandenen privaten Schlüssel erneuert; das alte öffentliche Zertifikat wurde gesichert. SMTP bleibt deaktiviert, Regeln wurden nicht aktiviert, keine Empfänger oder Benutzer angelegt.

## Bewusste Grenzen und Übergabe

Ohne genehmigte Quellfristen bleibt Freshness UNKNOWN. Envoyreadiness belegt keine externe Ende-zu-Ende-Verfügbarkeit; ohne unabhängigen Nachweis bleibt die entsprechende Fachprüfung UNKNOWN. Leerlauf ist nur bei vorhandener belastbarer Messung gesund. Wartung überschreibt den technischen Zustand nicht. Keine automatischen Reparaturen, keine freie URL-/SQL-/Shell-Diagnose, kein Docker-Socket und kein neuer öffentlicher Diagnoseendpunkt.

Es sind keine offenen Phase-22-Aufträge verbleibend. Übergreifendes Hardening und endgültige Produktionsfreigabe bleiben Gegenstand der nachfolgenden Phasen. [Übergabe](phase-22-handover.md).
