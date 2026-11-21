# Phase-20-Abnahme

Phase 20 ist vollständig umgesetzt und im vorhandenen Stack aktiviert. Alle 45 Aufträge
sind abgeschlossen; die [194 verbindlichen Kriterien](../testing/phase-20-test-matrix.md)
sind mit Codeprüfung, nativen Tests, Browsernachweisen und fachlichen Regressionen zugeordnet.

Das statische React-/TypeScript-Dashboard wird vom bestehenden Nginx über HTTPS ausgeliefert.
Login, MFA, Wiederherstellung, Sitzungsprüfung und Logout verwenden die vorhandenen Auth-APIs.
Übersicht, Server/Gruppen, Inventarqualität, Findings/Evidenz/Historie und Benachrichtigungen
arbeiten mit tatsächlichen Daten und aktuellen Objektberechtigungen. Es gibt keine
Verwaltungsmutationen oder Attrappen für Phase 21.

API 0.20.0 und Alembic-Head 00028_dashboard_reads sind aktiv. Die Migration ergänzt eine
minimierte Lesesicht und deren Leserechte. Kennzahlen filtern vor Aggregation im SQL-Scope;
Server-, Inventar- und Finding-Rechte bleiben getrennt. Fehlende Berechtigungen bzw. Quellen
werden nicht zu Nullbefunden. Letzter gültiger Snapshot und neuerer unvollständiger Versuch
sind getrennt sichtbar; ohne konfigurierte Policy wird keine Altersgrenze erfunden.

Die bestehende Finding-Liste erhält einen technischen Statusfilter. Notification-Liste und
-details liefern zusätzlich CVE-/Server-/Prioritätsreferenzen; Historie und Versuche sind
nun tatsächlich serverseitig paginiert. Aktuelle Priorität ist als solche beschriftet und
wird nicht als historische Versandpriorität ausgegeben. Relay-/Smarthost-Annahme und
nachgewiesene Zustellung bleiben getrennte Aussagen. Die neuen Projektionen schreiben
keine Finding-, Inventar- oder Versanddaten.

| Prüfung | Erfolgreiche Fälle |
|---|---:|
| Standardregression über make check | 551 |
| Authentifizierung, MFA, Autorisierung, Server/Gruppen | 146 |
| Findings und Notifications einschließlich SMTP-/n8n-/Recovery-Fällen | 174 |
| Infrastruktur, Nginx und vorhandene API-/Service-Container | 51 |
| Neue Vitest-/Komponenten-/Client-Sicherheitsfälle | 11 |
| Neue native Dashboardfälle mit echter Upload-/Matching-/Finding-/Notification-Pipeline | 2 |
| Chromium-Browserabläufe über tatsächliches HTTPS | 4 |

Nach der Ergänzung der Notification-Leseprojektion wurden deren vier vorhandene API-Fälle
zusätzlich erfolgreich nachgeprüft. Wiederholungen zählen nicht als neue Fälle. Die beiden
JUnit-Hinweise der Domain-Performancefälle zu record_property sind keine Testfehler.
Keine Remote-CI-Ausführung wird behauptet; die Workflow-Erweiterungen sind lokal validiert.

make check besteht: Ruff, Formatierung, striktes Mypy, 551 Standardfälle, Repository-/Schema-/
Compose-Validierung und Secretprüfung. Die vorhandene Secret-Baseline bleibt unverändert.
Frontend-Typecheck, ESLint 10, Vitest, reproduzierbares npm ci und Produktivbuild bestehen.
Der exportierte OpenAPI-Vertrag ist validiert. npm audit meldet null bekannte Schwachstellen;
das gezielte minimatch-Override 11.0.1 gilt auch für die ESLint-/TypeScript-Entwicklungswerkzeuge.

Die Browserfälle prüfen echte Navigation und Deep Links, Fehler/503 ohne Null-KPIs,
Viewer-Rechte, sichtbaren Tastaturfokus/Sprunglink, MFA mit falschem und gültigem Code,
Wiederherstellungscode-Anzeige, erneute MFA-Anmeldung, Logout in zwei Tabs, Browser-Zurück
und serverseitige Invalidierung. Alle neun Fachansichten bestehen axe-Prüfungen gegen
WCAG-2.2-AA-Tags. Layouts bei 320, 768 und 1440 px sind geprüft und als Screenshots gesichert.
Die automatische Prüfung und die ausgeführten Tastatur-/Layoutfälle sind keine Behauptung
einer vollständigen manuellen Screenreader-Zertifizierung.

CSP ohne unsafe-inline, Same-Origin, hostgebundene HttpOnly-Cookies, begrenzte Requests,
Cachebereinigung, keine persistenten Browsertokens, keine API-/Internal-SPA-Fallbacks sowie
unveränderte HSTS-Strategie sind nachgewiesen. Es gibt keinen Node-Produktivprozess, keinen
zusätzlichen Container/Port und keinen Browserzugriff auf Datenbank, SMTP, n8n oder Worker.

Lokale Performance-Baseline des Browserlaufs: FCP 140 ms, 11 Ressourcen,
151527 übertragene Bytes. Größter JavaScript-Teil: 218,75 kB unkomprimiert
(React, etwa 68,27 kB gzip); Routen werden getrennt geladen. Die Messung ist eine lokale
Baseline und keine allgemeine Produktionslatenz-Zusage. Gehashte Assets werden komprimiert
und immutable ausgeliefert, HTML und APIs mit no-store.

Der finale Livevergleich bestätigt 13 gesunde Dienste. Nur der API-Container wurde ersetzt;
Nginx wurde geprüft und neu geladen. 106 bestehende Fachtabellen sind per vollständigem
Fingerprint unverändert. 342 zuvor erfasste Python-Bestandsdateien sind hashgleich; fünf
bestehende API-Dateien registrieren Version/Router bzw. ergänzen die beschriebenen Reads.
Alle früheren Migrationen, Worker und cve_common bleiben unverändert. 87 API-Pythondateien
im laufenden Image und sämtliche aktivierten statischen Assets stimmen mit dem Workspace überein.

Die normale Umgebung enthält weiterhin keine Benutzer, Tokens, Inventare, CVE-Quellrecords,
Enrichment-/Matching-Ergebnisse, Findings, Notification Intents oder SMTP-Versuche. Testdaten
bleiben ausschließlich in isolierten, anschließend bereinigten Projekten. Mail-/Egress-Policy,
Bindings, menschlicher Berechtigungskatalog und vier fremde Nextcloud-Container sind unverändert.
Die Sicherung vor der Migration liegt privat unter .runtime/phase20-pre-migration.

Nachweise: .runtime/test-reports/phase-20-check.log, phase-20-dashboard-check.log,
phase-20-native.log/.xml, phase-20-playwright.json, phase-20-e2e.log,
phase-20-auth-regression.xml, phase-20-domain-regression.xml,
phase-20-notification-recheck.xml, phase-20-infra-regression.xml,
phase-20-npm-audit.json, phase-20-performance.json, phase-20-live-verification.json
sowie die Desktop-/Tablet-/Mobile-Screenshots. Betrieb und Rücknahme sind in
[Dashboard-Deployment](../operations/dashboard-deployment.md) beschrieben;
[Phase 21](phase-20-handover.md) übernimmt die schreibenden Verwaltungsdialoge.
