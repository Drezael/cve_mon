# Phase-7-Abnahme

Stand: 06.11.2026. **Status: completed — alle 45 Aufträge, 51 abschließenden Abnahmepunkte und 48 JOB-Invarianten nachgewiesen.**

687 Tests bestanden: 306 Standardtests (darunter 36 neue Automations-Unit-Tests),
29 neue Automations-Integrationstests, 10 Service-Integrationstests, 189 PostgreSQL-,
40 Infrastruktur-, 77 Envoy- und 36 Postfix-Tests. Keine übersprungenen Pflichtprüfungen.

`make check`, `make setup python-check`, unveränderte Secret-Baseline,
frische Offline-Installation aller drei 0.7.0-Wheels und `pip check` erfolgreich.
Mypy prüft 149 Quelldateien, Ruff und Formatprüfung erfolgreich.
[Testmatrix](../testing/phase-07-test-matrix.md), [Messbericht](../testing/phase-07-performance.md),
[45 Aufgaben](phase-07-status.md), [Dateiliste](phase-07-files.json).

## Abschließende Vorgaben aus Abschnitt 28

| Nr. | Vorgabe | Nachweis |
|---|---|---|
| 1 | Jobtabellen vollständig. | Migration 00013, native Rollen/Grants, test_events/test_jobs, 189 DB-Regressionstests |
| 2 | Outbox-Tabellen vollständig. | Migration 00013, native Rollen/Grants, test_events/test_jobs, 189 DB-Regressionstests |
| 3 | Migrationen erfolgreich. | Migration 00013, native Rollen/Grants, test_events/test_jobs, 189 DB-Regressionstests |
| 4 | Datenbankrechte korrekt. | Migration 00013, native Rollen/Grants, test_events/test_jobs, 189 DB-Regressionstests |
| 5 | Indizes vorhanden. | Migration 00013, native Rollen/Grants, test_events/test_jobs, 189 DB-Regressionstests |
| 6 | Keine zusätzliche Queue-Infrastruktur. | Migration 00013, native Rollen/Grants, test_events/test_jobs, 189 DB-Regressionstests |
| 7 | Job-Erstellung funktioniert. | 36 Vertrags-Unit-Tests; test_jobs, test_workers und parallele Claim-/Fencing-Tests |
| 8 | Payloadvalidierung funktioniert. | 36 Vertrags-Unit-Tests; test_jobs, test_workers und parallele Claim-/Fencing-Tests |
| 9 | Idempotenz funktioniert. | 36 Vertrags-Unit-Tests; test_jobs, test_workers und parallele Claim-/Fencing-Tests |
| 10 | Atomare Reservierung funktioniert. | 36 Vertrags-Unit-Tests; test_jobs, test_workers und parallele Claim-/Fencing-Tests |
| 11 | Mehrere Worker funktionieren. | 36 Vertrags-Unit-Tests; test_jobs, test_workers und parallele Claim-/Fencing-Tests |
| 12 | Keine gültigen Doppelreservierungen. | 36 Vertrags-Unit-Tests; test_jobs, test_workers und parallele Claim-/Fencing-Tests |
| 13 | Leases funktionieren. | 36 Vertrags-Unit-Tests; test_jobs, test_workers und parallele Claim-/Fencing-Tests |
| 14 | Heartbeats funktionieren. | 36 Vertrags-Unit-Tests; test_jobs, test_workers und parallele Claim-/Fencing-Tests |
| 15 | Fencing funktioniert. | 36 Vertrags-Unit-Tests; test_jobs, test_workers und parallele Claim-/Fencing-Tests |
| 16 | Worker-Abstürze werden behandelt. | test_resilience: reale SIGKILL/SIGTERM, Persistenz, Übernahme, Retrylimit/Deadline; Worker-Tests |
| 17 | Jobs bleiben persistent. | test_resilience: reale SIGKILL/SIGTERM, Persistenz, Übernahme, Retrylimit/Deadline; Worker-Tests |
| 18 | Leases laufen kontrolliert ab. | test_resilience: reale SIGKILL/SIGTERM, Persistenz, Übernahme, Retrylimit/Deadline; Worker-Tests |
| 19 | Verwaiste Jobs werden erneut bearbeitbar. | test_resilience: reale SIGKILL/SIGTERM, Persistenz, Übernahme, Retrylimit/Deadline; Worker-Tests |
| 20 | Temporäre Fehler werden wiederholt. | test_resilience: reale SIGKILL/SIGTERM, Persistenz, Übernahme, Retrylimit/Deadline; Worker-Tests |
| 21 | Permanente Fehler werden abgelegt. | test_resilience: reale SIGKILL/SIGTERM, Persistenz, Übernahme, Retrylimit/Deadline; Worker-Tests |
| 22 | Kontrollierter Shutdown funktioniert. | test_resilience: reale SIGKILL/SIGTERM, Persistenz, Übernahme, Retrylimit/Deadline; Worker-Tests |
| 23 | Fachänderung und Event atomar. | test_events und test_dispatcher: atomarer Commit/Rollback, HTTPS, Ack-Verlust, Consumer-Race |
| 24 | Keine Events aus zurückgerollten Transaktionen. | test_events und test_dispatcher: atomarer Commit/Rollback, HTTPS, Ack-Verlust, Consumer-Race |
| 25 | Dispatcher funktioniert. | test_events und test_dispatcher: atomarer Commit/Rollback, HTTPS, Ack-Verlust, Consumer-Race |
| 26 | Zustellversuche persistent. | test_events und test_dispatcher: atomarer Commit/Rollback, HTTPS, Ack-Verlust, Consumer-Race |
| 27 | Zustellfehler nachvollziehbar. | test_events und test_dispatcher: atomarer Commit/Rollback, HTTPS, Ack-Verlust, Consumer-Race |
| 28 | Wiederholungen funktionieren. | test_events und test_dispatcher: atomarer Commit/Rollback, HTTPS, Ack-Verlust, Consumer-Race |
| 29 | Doppelte Zustellungen werden berücksichtigt. | test_events und test_dispatcher: atomarer Commit/Rollback, HTTPS, Ack-Verlust, Consumer-Race |
| 30 | Idempotente Consumer-Grundlage vorhanden. | test_events und test_dispatcher: atomarer Commit/Rollback, HTTPS, Ack-Verlust, Consumer-Race |
| 31 | Keine unregistrierten Jobhandler. | Registry/JSON-Verträge; negative Rollen-/TLS-/Auth-/Redirecttests; unveränderte Secret-Baseline |
| 32 | Keine dynamische Codeausführung. | Registry/JSON-Verträge; negative Rollen-/TLS-/Auth-/Redirecttests; unveränderte Secret-Baseline |
| 33 | Keine beliebigen Zieladressen. | Registry/JSON-Verträge; negative Rollen-/TLS-/Auth-/Redirecttests; unveränderte Secret-Baseline |
| 34 | Datenbankrechte begrenzt. | Registry/JSON-Verträge; negative Rollen-/TLS-/Auth-/Redirecttests; unveränderte Secret-Baseline |
| 35 | Keine administrativen Gruppenänderungen. | Registry/JSON-Verträge; negative Rollen-/TLS-/Auth-/Redirecttests; unveränderte Secret-Baseline |
| 36 | Keine Secrets in Logs. | Registry/JSON-Verträge; negative Rollen-/TLS-/Auth-/Redirecttests; unveränderte Secret-Baseline |
| 37 | Keine unnötigen öffentlichen Endpunkte. | Registry/JSON-Verträge; negative Rollen-/TLS-/Auth-/Redirecttests; unveränderte Secret-Baseline |
| 38 | Event Dispatcher läuft in Docker. | test_dispatcher: Docker/Health/DB-Ausfall/Neustart/SIGKILL; native Metrics; lokaler gesunder Dienst |
| 39 | Healthchecks funktionieren. | test_dispatcher: Docker/Health/DB-Ausfall/Neustart/SIGKILL; native Metrics; lokaler gesunder Dienst |
| 40 | Metriken vorhanden. | test_dispatcher: Docker/Health/DB-Ausfall/Neustart/SIGKILL; native Metrics; lokaler gesunder Dienst |
| 41 | Queue-Rückstände erkennbar. | test_dispatcher: Docker/Health/DB-Ausfall/Neustart/SIGKILL; native Metrics; lokaler gesunder Dienst |
| 42 | Neustarttests erfolgreich. | test_dispatcher: Docker/Health/DB-Ausfall/Neustart/SIGKILL; native Metrics; lokaler gesunder Dienst |
| 43 | Absturztests erfolgreich. | test_dispatcher: Docker/Health/DB-Ausfall/Neustart/SIGKILL; native Metrics; lokaler gesunder Dienst |
| 44 | Konkurrenztests erfolgreich. | test_dispatcher: Docker/Health/DB-Ausfall/Neustart/SIGKILL; native Metrics; lokaler gesunder Dienst |
| 45 | Ruff erfolgreich. | make check, setup/python-check, frische Wheel-Installation; Testmatrix und Übergabe |
| 46 | Mypy erfolgreich. | make check, setup/python-check, frische Wheel-Installation; Testmatrix und Übergabe |
| 47 | Unit-Tests erfolgreich. | make check, setup/python-check, frische Wheel-Installation; Testmatrix und Übergabe |
| 48 | Integrationstests erfolgreich. | make check, setup/python-check, frische Wheel-Installation; Testmatrix und Übergabe |
| 49 | Sicherheitstests erfolgreich. | make check, setup/python-check, frische Wheel-Installation; Testmatrix und Übergabe |
| 50 | Dokumentation vollständig. | make check, setup/python-check, frische Wheel-Installation; Testmatrix und Übergabe |
| 51 | Übergabe an Phase 8 vorbereitet. | make check, setup/python-check, frische Wheel-Installation; Testmatrix und Übergabe |

## Verbindliche Invarianten

| ID | Regel | Nachweis |
|---|---|---|
| JOB-01 | PostgreSQL ist die einzige persistente Jobdatenbank | Compose/Architektur: ausschließlich PostgreSQL, keine zusätzlichen Queuedienste |
| JOB-02 | Kein Redis | Compose/Architektur: ausschließlich PostgreSQL, keine zusätzlichen Queuedienste |
| JOB-03 | Kein zusätzlicher Message Broker | Compose/Architektur: ausschließlich PostgreSQL, keine zusätzlichen Queuedienste |
| JOB-04 | Keine zusätzliche Workflow-Engine | Compose/Architektur: ausschließlich PostgreSQL, keine zusätzlichen Queuedienste |
| JOB-05 | Jobtypen werden ausdrücklich registriert | Registry/Enqueue-Verträge und test_contracts/test_jobs |
| JOB-06 | Keine dynamische Codeausführung aus Payloads | Registry/Enqueue-Verträge und test_contracts/test_jobs |
| JOB-07 | Jobdaten werden vor Ausführung persistent gespeichert | Registry/Enqueue-Verträge und test_contracts/test_jobs |
| JOB-08 | Job-Payloads werden validiert | Registry/Enqueue-Verträge und test_contracts/test_jobs |
| JOB-09 | Job-Erstellung unterstützt Idempotenz | Registry/Enqueue-Verträge und test_contracts/test_jobs |
| JOB-10 | Reservierungen erfolgen atomar | Native SKIP LOCKED/Token/Epoch/DB-Uhr; test_jobs/test_workers/test_resilience |
| JOB-11 | Mehrere Worker dürfen keine gültige Doppelreservierung erzeugen | Native SKIP LOCKED/Token/Epoch/DB-Uhr; test_jobs/test_workers/test_resilience |
| JOB-12 | Reservierungstransaktionen bleiben kurz | Native SKIP LOCKED/Token/Epoch/DB-Uhr; test_jobs/test_workers/test_resilience |
| JOB-13 | Leases besitzen eine Ablaufzeit | Native SKIP LOCKED/Token/Epoch/DB-Uhr; test_jobs/test_workers/test_resilience |
| JOB-14 | Nur der aktuelle Worker darf seine Lease verlängern | Native SKIP LOCKED/Token/Epoch/DB-Uhr; test_jobs/test_workers/test_resilience |
| JOB-15 | Veraltete Worker dürfen keine Ergebnisse committen | Native SKIP LOCKED/Token/Epoch/DB-Uhr; test_jobs/test_workers/test_resilience |
| JOB-16 | Abgestürzte Worker blockieren Jobs nicht dauerhaft | Native SKIP LOCKED/Token/Epoch/DB-Uhr; test_jobs/test_workers/test_resilience |
| JOB-17 | Wiederholungen sind begrenzt | Begrenzte Retry-/Control-Funktionen, Historie, Replay; test_jobs/test_resilience |
| JOB-18 | Permanente Fehler werden nicht endlos wiederholt | Begrenzte Retry-/Control-Funktionen, Historie, Replay; test_jobs/test_resilience |
| JOB-19 | Jobversuche werden historisiert | Begrenzte Retry-/Control-Funktionen, Historie, Replay; test_jobs/test_resilience |
| JOB-20 | Dead-Letter-Jobs bleiben nachvollziehbar | Begrenzte Retry-/Control-Funktionen, Historie, Replay; test_jobs/test_resilience |
| JOB-21 | Jobabbrüche sind kontrolliert | Begrenzte Retry-/Control-Funktionen, Historie, Replay; test_jobs/test_resilience |
| JOB-22 | Worker-Parallelität ist begrenzt | WorkerSettings/individuelle Transaktionen; Worker-/Performance-/Pooltests |
| JOB-23 | Datenbankverbindungen sind begrenzt | WorkerSettings/individuelle Transaktionen; Worker-/Performance-/Pooltests |
| JOB-24 | Keine unkontrollierten globalen AsyncSessions | WorkerSettings/individuelle Transaktionen; Worker-/Performance-/Pooltests |
| JOB-25 | Fachänderung und Outbox-Ereignis verwenden dieselbe Transaktion | Atomare Outbox/Consumer-Markierung, HTTPS-Wiederholung; test_events/test_dispatcher |
| JOB-26 | Kein Event aus einer zurückgerollten Fachtransaktion | Atomare Outbox/Consumer-Markierung, HTTPS-Wiederholung; test_events/test_dispatcher |
| JOB-27 | Committete Events werden persistent aufbewahrt | Atomare Outbox/Consumer-Markierung, HTTPS-Wiederholung; test_events/test_dispatcher |
| JOB-28 | Event Dispatcher arbeitet unabhängig von Fachtransaktionen | Atomare Outbox/Consumer-Markierung, HTTPS-Wiederholung; test_events/test_dispatcher |
| JOB-29 | Eventzustellungen unterstützen Wiederholungen | Atomare Outbox/Consumer-Markierung, HTTPS-Wiederholung; test_events/test_dispatcher |
| JOB-30 | Doppelte Zustellung wird berücksichtigt | Atomare Outbox/Consumer-Markierung, HTTPS-Wiederholung; test_events/test_dispatcher |
| JOB-31 | Keine pauschale Exactly-once-Garantie | Atomare Outbox/Consumer-Markierung, HTTPS-Wiederholung; test_events/test_dispatcher |
| JOB-32 | Event-Verträge sind versioniert | Atomare Outbox/Consumer-Markierung, HTTPS-Wiederholung; test_events/test_dispatcher |
| JOB-33 | Ereignisse enthalten keine Zugangsdaten | Private Target-Registry und Transport, URL/CA/Auth-Negativtests |
| JOB-34 | Keine frei wählbaren Transportziele aus Events | Private Target-Registry und Transport, URL/CA/Auth-Negativtests |
| JOB-35 | Transportziele müssen autorisiert sein | Private Target-Registry und Transport, URL/CA/Auth-Negativtests |
| JOB-36 | TLS-Prüfung bleibt aktiv | Private Target-Registry und Transport, URL/CA/Auth-Negativtests |
| JOB-37 | Kein allgemeiner öffentlicher Job-Endpunkt | Keine öffentlichen Jobrouten, native Fachrechte, Docker-Härtung und Regression |
| JOB-38 | Kein allgemeiner öffentlicher Dispatcher-Endpunkt | Keine öffentlichen Jobrouten, native Fachrechte, Docker-Härtung und Regression |
| JOB-39 | Keine automatischen Servergruppenänderungen | Keine öffentlichen Jobrouten, native Fachrechte, Docker-Härtung und Regression |
| JOB-40 | Keine automatische Primärgruppenänderung | Keine öffentlichen Jobrouten, native Fachrechte, Docker-Härtung und Regression |
| JOB-41 | Keine automatische manuelle Sortieränderung | Keine öffentlichen Jobrouten, native Fachrechte, Docker-Härtung und Regression |
| JOB-42 | Kein direkter administrativer Schreibzugriff durch allgemeine Worker | Keine öffentlichen Jobrouten, native Fachrechte, Docker-Härtung und Regression |
| JOB-43 | Keine unnötigen privilegierten Container | Keine öffentlichen Jobrouten, native Fachrechte, Docker-Härtung und Regression |
| JOB-44 | Kein Docker-Socket | Keine öffentlichen Jobrouten, native Fachrechte, Docker-Härtung und Regression |
| JOB-45 | Keine Secrets in Logs | Redigierte strukturierte Logs, Runtime-/Dispatcher-Logs geprüft; Secret-Scan |
| JOB-46 | Healthchecks führen keine fachlichen Schreiboperationen aus | Readiness/Live/metrics ohne Fachwrites; echte DB-Ausfalltests |
| JOB-47 | Wiederherstellung nach Abstürzen wird praktisch geprüft | Prozess-SIGKILL/SIGTERM, Docker-Kill und negative Rollen/Fencing/TLS/Auth-Tests |
| JOB-48 | Sicherheitsrelevante Negativtests sind verpflichtend | Prozess-SIGKILL/SIGTERM, Docker-Kill und negative Rollen/Fencing/TLS/Auth-Tests |

## Lokaler Betrieb und Rückwirkungen

Migration 00013_automation_runtime angewendet. PostgreSQL, API 0.7.0, Envoy,
Postfix und Event Dispatcher 0.7.0 gesund. Dispatcher ohne Hostports, nur interne
Netze, Nicht-Root/readonly, eigene private Credentials. Live/Ready/metrics liefern 200.
Zielregistry ist leer; keine produktiven Testhandler, Testevents oder Consumer angelegt.
Vorhandene Jobtypen bleiben erhalten; Legacy-Zeilen werden nicht automatisch ausgeführt.

Die vier fremden Nextcloud-Container behalten ihre IDs. Originale in dev_docs,
bisherige zwölf Migrationen, Phase-0-Fachverträge und Secret-Baseline unverändert.
Rückwirkungen beschränken sich auf kompatible Paket-/Imageversionen, Dispatcher-
Compose/Bootstrap/Konfiguration, technische Verträge und Prüfwerkzeuge.
Sämtliche bisherigen Komponenten wurden mit ihren realen Integrationssuiten geprüft.

## Betriebsgrenzen und Übergabe

At-least-once mit Fencing und idempotenten Effekten; externe Effekte benötigen weiterhin
Empfänger-Idempotenz. Automatische Wiederholungen sind begrenzt. Endgültige Fehler
bleiben sichtbar; expliziter Job-Replay erzeugt eine neue ID. Ein Delivery-Retry erweitert
das Budget auditierbar bis maximal 100, ohne Versuchszähler oder Historie zurückzusetzen.

Neue fachliche Handler, authentifizierte Fach-APIs, n8n-Ziele und produktive PKI werden
in ihren Folgephasen ergänzt. Phase 8 wurde nicht begonnen. Keine offenen verpflichtenden
lokalen Phase-7-Arbeiten. Ein gehosteter CI-Lauf ist mangels Veröffentlichung nicht erfolgt;
kein Commit/Push. Lokale Prüflogs und Messdaten liegen ignoriert unter .runtime/test-reports.

[Übergabe an Phase 8](phase-07-handover.md).
