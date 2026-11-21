# Phase-21-Abnahme

Phase 21 vollständig umgesetzt und lokal aktiviert. Alle 45 Einzelaufträge abgeschlossen;
alle 180 Pflichtkriterien aus T21.09.05 sind in der [Testmatrix](../testing/phase-21-test-matrix.md)
Codeprüfung und dynamischen Nachweisen zugeordnet. Der bestehende Frontend-/API-/Nginx-Stack
bleibt erhalten. Kein zweites Frontend, kein weiterer Dienst oder fachlicher Mutationsweg.

## Funktionsumfang

Serverregistrierung und Metadaten, Archivierung/Wiederaktivierung; Gruppen, explizite
Mitgliedschaften und Primärgruppen; drei unabhängige Sortierscopes mit Tastaturbedienung;
berechtigter unveränderter JSON-Upload und getrennte Annahme-/Verarbeitungsanzeige;
Finding-Triage, Zuständigkeiten, Notizen, Reviews, Maßnahmen, endliche Risikoausnahmen
und bestehender Finding-Abschluss; Benutzer, delegierbare Rollen, effektive Rechte,
explizite Server-ACLs und bestehende Kontosicherheit; Präferenzen, Regeln, Vorlagenversionen,
sichere synthetische Vorschau und minimierte Auditansicht.

CSRF für sämtliche Mutationen, serverseitige aktuelle Rechte, kritische Bestätigung und
MFA-Step-up, Versionskonflikte ohne stilles Überschreiben, Entwurfsschutz und begrenzte
Anfragen. Kein automatischer Schreibretry. Rechteänderungen invalidieren bestehende
Sitzungen gemäß unverändertem Backendvertrag. Der Browsertest prüft Grant und Entzug
jeweils mit anschließendem geschütztem Lesen.

Endgültiges Serverlöschen, neue Passwort-Reset-Ausstellung, gespeicherte Ansichten/Exporte
und freier SMTP-Testversand sind mangels freigegebenem Backendvertrag bewusst nicht als
Bedienfunktion verfügbar. Dies entspricht den bedingten Anforderungen des Phasenplans;
keine Ersatz- oder Scheinimplementierungen. Details: [Übergabe](phase-21-handover.md).

## Erfolgreiche Prüfungen

| Prüfung | Ergebnis | Nachweis unter .runtime/test-reports/ |
|---|---:|---|
| Standardtests, Ruff/Format, Mypy, Repository und Secretprüfung | 551 Tests | phase-21-check.log |
| Auth-/RBAC-/Server-/Gruppen-/Sortierregression | 146 Tests | phase-21-auth-regression.xml |
| Finding-/Benachrichtigungsregression | 174 Tests | phase-21-domain-regression.xml |
| Infrastruktur, TLS, Nginx und Dienste | 51 Tests | phase-21-infrastructure.xml |
| Neue echte API-/Upload-/Processing-/Größengrenzen und Browserharness | 3 Tests | phase-21-native.xml |
| Bestehendes Dashboard einschließlich Auth/MFA/Lesescope | 2 native + 4 Browserfälle | phase-21-dashboard-regression.xml, phase-20-playwright.json |
| Frontend-Komponenten, Validierung, CSRF, Konflikt, Entwurf und Schreibretry | 20 Tests | phase-21-vitest.log |
| Wiederholung des Browserharness gegen den finalen Build | 1 Harness, dieselben 9 Browserfälle | phase-21-final-browser.xml |
| Verwaltungsbrowser, reale Mutationen, ACL, Konflikt, MFA, Upload, XSS, WCAG und Responsive/Performance | 9 Browserfälle | phase-21-playwright.json |
| Frontend-Typecheck, Lint und Produktionsbuild | erfolgreich | phase-21-dashboard-build.log, phase-21-dashboard-lint.log |

Die zwei bekannten pytest-record_property/JUnit-Formatwarnungen der bestehenden
Domain-Performancetests betreffen ausschließlich die XML-Metadaten; sämtliche Tests bestehen.

## Performance und Zugänglichkeit

Chromium mit tatsächlichem TLS-/API-/PostgreSQL-Pfad. Jede Messung lädt die Verwaltungsseite
mit bestätigter serverseitiger Liste, maximal 25 Einträgen und einem Budget von 8 Sekunden.
Kein einzelner JavaScript-Chunk überschreitet 300000 Bytes. Adminbereich wird nachgeladen;
alle Assets bleiben lokal. Dies ist die lokale Entwicklungsbaseline.

| Viewport | Seite mit API-Daten | Zeilen | Listenantwort |
|---|---:|---:|---:|
| 320 px | 530 ms | 2 | 726 B |
| 768 px | 417 ms | 2 | 726 B |
| 1440 px | 444 ms | 2 | 726 B |

Messwerte und rohe/gzip-Chunkgrößen: phase-21-performance.json. Screenshots für 320/768/1440 px,
keine horizontale Seitenüberbreite; axe WCAG 2/2.1/2.2 AA ohne Verstöße in den geprüften
Verwaltungsansichten, Formularen und Dialogen. Tastaturalternative für Sortierung und
Fokusführung in nativen modalen Dialogen.

## Lokale Aktivierung und Datenbestand

Backup vor Migration: .runtime/phase21-pre-migration. Datenbankkopf
00029_dashboard_administration, API 0.21.0 (cve-api:0.21.0-phase21), statische Dateien im
vorhandenen Nginx-Mount. Alle 13 normalen Dienste gesund. Live-Prüfung:
phase-21-live-verification.json. Container-API mit allen 88 Python-Dateien und
statisches Build stimmen mit dem Repository überein. HTTPS, CSP, no-store, gzip und immutable
Assets geprüft; Verwaltungs-API ohne Session 401; unbekannte API-/interne Wege 404.

134 bestehende Anwendungstabellen und 154 geschützte n8n-Tabellen
inhaltlich unverändert. Laufende Job-/Workflow-Ausführungsprotokolle sind von diesen
Fachdatengleichheitsprüfungen ausgenommen; die Alembic-Kopfrevision wurde gezielt angehoben.
350 vorhandene Python-Dateien unverändert; drei erwartete API-Änderungen
betreffen Routerregistrierung/Version und die explizite administrative Bodygrößen-Whitelist.
Keine Änderungen an Fachzustandsmaschinen, menschlichem Permissionkatalog,
Envoy-/Mailpolicies und Bindings. Nur der API-Container wurde ersetzt; fremde vier
Nextcloud-Container unverändert. Normale Benutzer, Tokens, Server, Inventare, CVEs,
Findings und Notification-Intents weiterhin leer; keine Versandregel aktiviert.
Kein SSH-/Ansible-Zielzugriff oder realer Mailversand zur Aktivierung.

Betrieb/Rollback: [Dashboard-Deployment](../operations/dashboard-deployment.md).
