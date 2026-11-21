# Phase-10-Abnahme

Stand: 07.11.2026. **Status: completed — alle 45 Aufträge, 78 Pflichtprüfungen,
55 SRV-Invarianten und 47 Schlusskriterien lokal nachgewiesen.**

972 verschiedene Tests bestanden: 445 Standardtests (einschließlich 56 neuer Phase-10-
Unit-/Vertragstests), 53 Serververwaltungs-Integrationstests, 37 Autorisierungs-,
56 Authentifizierungs-, 29 Job-/Outbox-, 10 Service-, 189 PostgreSQL-,
40 Infrastruktur-, 77 Envoy- und 36 Postfix-Tests. Standardauswahl und gesonderte
Docker-Suiten überschneiden sich nicht. Keine verpflichtenden lokalen Prüfungen ausgelassen.

make check, setup/python-check, Ruff/Format, Mypy (249 Quelldateien), alle JSON-/OpenAPI-
Verträge, beide Compose-Modelle und Secret-Scan erfolgreich. Baseline unverändert.
Frische Offline-venv aus Hash-geprüften Runtime-Wheels plus lokalen Projektwheels:
API 0.10.0, common/Dispatcher 0.7.0, pip check, isolierte Imports ohne Netzwerk und
mitgelieferte Passwortblocklist/Lizenz geprüft. Keine externe Dependencyänderung.
Additive Revision 00016 auf frischer und bestehender Datenbank, wiederholte Migration
und Restore in der nativen DB-Suite geprüft. Alle älteren Migrationen und Originalkonzepte
bleiben unverändert; vorhandene technische Dienste und frühere Verträge berücksichtigt.

[45 Aufgaben](phase-10-status.md), [Dateimanifest](phase-10-files.json),
[Testmatrix](../testing/phase-10-test-matrix.md), [Lastmessung](../testing/phase-10-performance.md),
[Übergabe](phase-10-handover.md), Bestands-/Gap-Analyse (nur lokal archiviert).

## Verpflichtende Prüfungen T10.09.05

Alle Zeilen bestanden. Testdateinamen beziehen sich auf tests/server_administration/integration/.

| Nr. | Vorgabe | Nachweis |
|---|---|---|
| 1 | Vorhandene Datenbankstrukturen berücksichtigt. | 00016; frische/repetierte Migration, 189 native DB-Tests und tatsächliche Rollenlogins |
| 2 | Alle Migrationen versioniert. | 00016; frische/repetierte Migration, 189 native DB-Tests und tatsächliche Rollenlogins |
| 3 | Datenbankrechte korrekt. | 00016; frische/repetierte Migration, 189 native DB-Tests und tatsächliche Rollenlogins |
| 4 | Kein zusätzlicher Datenbankdienst. | 00016; frische/repetierte Migration, 189 native DB-Tests und tatsächliche Rollenlogins |
| 5 | Keine PostgreSQL-Superuser-Rechte für die API. | 00016; frische/repetierte Migration, 189 native DB-Tests und tatsächliche Rollenlogins |
| 6 | Serverregistrierung funktioniert. | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| 7 | Server-UUID eindeutig. | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| 8 | Server-UUID unveränderlich. | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| 9 | Keine automatische Registrierung über Inventare. | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| 10 | Administrative Servermetadaten bearbeitbar. | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| 11 | Technische Inventarfelder nicht administrativ überschreibbar. | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| 12 | Serverarchivierung funktioniert. | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| 13 | Serverwiederherstellung funktioniert. | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| 14 | Historische Daten bleiben erhalten. | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| 15 | Gruppenregistrierung funktioniert. | test_lifecycle.py/test_ordering.py: normalisierte Namen, Metadaten, leere Gruppe, Archive/Restore und Rennen |
| 16 | Gruppen-UUID unveränderlich. | test_lifecycle.py/test_ordering.py: normalisierte Namen, Metadaten, leere Gruppe, Archive/Restore und Rennen |
| 17 | Gruppenmetadaten bearbeitbar. | test_lifecycle.py/test_ordering.py: normalisierte Namen, Metadaten, leere Gruppe, Archive/Restore und Rennen |
| 18 | Gruppenarchivierung funktioniert. | test_lifecycle.py/test_ordering.py: normalisierte Namen, Metadaten, leere Gruppe, Archive/Restore und Rennen |
| 19 | Belegte Gruppe kann nicht archiviert werden. | test_lifecycle.py/test_ordering.py: normalisierte Namen, Metadaten, leere Gruppe, Archive/Restore und Rennen |
| 20 | Gruppenwiederherstellung funktioniert. | test_lifecycle.py/test_ordering.py: normalisierte Namen, Metadaten, leere Gruppe, Archive/Restore und Rennen |
| 21 | Mehrfachgruppenmitgliedschaft funktioniert. | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| 22 | Doppelte Mitgliedschaften verhindert. | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| 23 | Server ohne Gruppe zulässig. | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| 24 | Server mit einer Gruppe besitzt diese als Primärgruppe. | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| 25 | Server mit mehreren Gruppen besitzt genau eine Primärgruppe. | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| 26 | Primärgruppe gehört zur Mitgliedschaft. | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| 27 | Primärgruppenwechsel funktioniert. | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| 28 | Ungültige Primärgruppe abgelehnt. | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| 29 | Entfernen der Primärgruppe ohne Ersatz wird gegebenenfalls abgelehnt. | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| 30 | Entfernen der letzten Gruppe setzt Primärgruppe auf `NULL`. | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| 31 | Gruppensortierung funktioniert. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 32 | Globale Serversortierung funktioniert. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 33 | Gruppeninterne Serversortierung funktioniert. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 34 | Sortierung einer Gruppe verändert keine andere Gruppe. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 35 | Sortierpositionen sind persistent. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 36 | Archivierung beschädigt keine Sortierreihenfolge. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 37 | Wiederherstellung erhält eine konsistente Reihenfolge. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 38 | Versionskontrolle funktioniert. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 39 | Veraltete Änderungen werden erkannt. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 40 | Parallele Gruppenänderungen sind sicher. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 41 | Parallele Primärgruppenänderungen sind sicher. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 42 | Parallele Sortieränderungen sind sicher. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 43 | Gruppenarchivierung und Mitgliedschaftsänderung sind konkurrierend sicher. | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| 44 | Admin-Berechtigungen werden geprüft. | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| 45 | User Admin kann keine Gruppen administrieren. | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| 46 | Viewer kann keine Server administrieren. | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| 47 | Security Analyst kann keine Sortierung verändern. | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| 48 | CSRF funktioniert. | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| 49 | Reauthentifizierung bei kritischen Aktionen funktioniert. | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| 50 | ACL-gefilterte Serverlisten funktionieren. | test_security.py/test_recovery_performance.py: SQL-ACL vor Suche/Pagination/Zählung, BOLA/Mass Assignment negativ |
| 51 | ACL-gefilterte Gruppenlisten funktionieren. | test_security.py/test_recovery_performance.py: SQL-ACL vor Suche/Pagination/Zählung, BOLA/Mass Assignment negativ |
| 52 | Suchabfragen berücksichtigen ACLs. | test_security.py/test_recovery_performance.py: SQL-ACL vor Suche/Pagination/Zählung, BOLA/Mass Assignment negativ |
| 53 | Pagination berücksichtigt ACLs. | test_security.py/test_recovery_performance.py: SQL-ACL vor Suche/Pagination/Zählung, BOLA/Mass Assignment negativ |
| 54 | Aggregationen berücksichtigen ACLs. | test_security.py/test_recovery_performance.py: SQL-ACL vor Suche/Pagination/Zählung, BOLA/Mass Assignment negativ |
| 55 | Kein BOLA in den getesteten Endpunkten. | test_security.py/test_recovery_performance.py: SQL-ACL vor Suche/Pagination/Zählung, BOLA/Mass Assignment negativ |
| 56 | Kein Mass Assignment. | test_security.py/test_recovery_performance.py: SQL-ACL vor Suche/Pagination/Zählung, BOLA/Mass Assignment negativ |
| 57 | Technische Upload-Identitäten besitzen keine Verwaltungsrechte. | test_security.py: echte technische DB-Logins, verschachtelte normalisierte Inventarfelder, bestehende FK/Snapshot-Guards |
| 58 | Inventar-Uploads verändern keine Gruppen. | test_security.py: echte technische DB-Logins, verschachtelte normalisierte Inventarfelder, bestehende FK/Snapshot-Guards |
| 59 | Inventar-Uploads verändern keine Primärgruppen. | test_security.py: echte technische DB-Logins, verschachtelte normalisierte Inventarfelder, bestehende FK/Snapshot-Guards |
| 60 | Inventar-Uploads verändern keine Sortierpositionen. | test_security.py: echte technische DB-Logins, verschachtelte normalisierte Inventarfelder, bestehende FK/Snapshot-Guards |
| 61 | Technische Inventar-Datenbankrollen besitzen keine administrativen Schreibrechte. | test_security.py: echte technische DB-Logins, verschachtelte normalisierte Inventarfelder, bestehende FK/Snapshot-Guards |
| 62 | Audit funktioniert. | test_security.py/test_recovery_performance.py: Audit-ID/Digest, gemeinsamer Outbox-Commit, Fault-Rollback, Secret-Scan |
| 63 | Transactional Outbox funktioniert. | test_security.py/test_recovery_performance.py: Audit-ID/Digest, gemeinsamer Outbox-Commit, Fault-Rollback, Secret-Scan |
| 64 | Keine Secrets in Logs. | test_security.py/test_recovery_performance.py: Audit-ID/Digest, gemeinsamer Outbox-Commit, Fault-Rollback, Secret-Scan |
| 65 | Kein neuer öffentlicher Backend-Hostport. | 40 Infrastruktur- und 10 Service-Regressionstests; sechs eigene Dienste healthy und interne Backendports |
| 66 | Kein Docker-Socket. | 40 Infrastruktur- und 10 Service-Regressionstests; sechs eigene Dienste healthy und interne Backendports |
| 67 | Keine unnötigen Containerprivilegien. | 40 Infrastruktur- und 10 Service-Regressionstests; sechs eigene Dienste healthy und interne Backendports |
| 68 | Unit-Tests erfolgreich. | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |
| 69 | PostgreSQL-Integrationstests erfolgreich. | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |
| 70 | API-Integrationstests erfolgreich. | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |
| 71 | Sicherheitstests erfolgreich. | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |
| 72 | Konkurrenztests erfolgreich. | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |
| 73 | End-to-End-Test erfolgreich. | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |
| 74 | Performance-Baseline dokumentiert. | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |
| 75 | Dokumentation vollständig. | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |
| 76 | Übergabe an Phase 11 vorbereitet. | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |
| 77 | Keine Fachfunktionen späterer Phasen vorzeitig implementiert. | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |
| 78 | Keine unzulässigen Architekturänderungen. | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |

## Sicherheits- und Integritätsinvarianten

Alle 55 Regeln im implementierten lokalen Umfang erfüllt. Noch nicht veröffentlichte
Upload-/Verarbeitungswege bleiben gesperrt und müssen diese vorbereiteten Grenzen in
Phase 11/14 unverändert übernehmen. Keine Behauptung bereits implementierter Uploadfunktionen.

| ID | Regel | Nachweis |
|---|---|---|
| SRV-01 | Ein Server wird ausschließlich administrativ registriert | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| SRV-02 | Die Server-UUID wird serverseitig erzeugt | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| SRV-03 | Die Server-UUID bleibt unveränderlich | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| SRV-04 | Ein unbekannter Server wird nicht durch Inventar-Upload automatisch registriert | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| SRV-05 | Administrative Metadaten bleiben von technischen Inventardaten getrennt | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| SRV-06 | Inventar-Uploads verändern keine administrativen Serverstammdaten | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| SRV-07 | Ein Server darf mehreren Gruppen angehören | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| SRV-08 | Doppelte Gruppenmitgliedschaften sind nicht zulässig | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| SRV-09 | Ein Server mit Gruppen besitzt genau eine Primärgruppe | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| SRV-10 | Ein Server ohne Gruppen besitzt keine Primärgruppe | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| SRV-11 | Die Primärgruppe muss Mitgliedschaft sein | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| SRV-12 | Die Primärgruppe darf keine archivierte Gruppe sein | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| SRV-13 | Primärgruppenänderungen erfolgen ausdrücklich administrativ | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| SRV-14 | Keine automatische Ersatzprimärgruppe | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| SRV-15 | Mitgliedschaftsänderungen erfolgen atomar | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| SRV-16 | Gruppenarchivierung erfolgt nur bei vollständig leerer Gruppe | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| SRV-17 | Keine implizite Umgruppierung durch Gruppenarchivierung | test_lifecycle.py/test_security.py/test_ordering.py: explizite Primärmitgliedschaft, native Deferred-Checks, Rollback |
| SRV-18 | Serverarchivierung löscht keine historische Inventardaten | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| SRV-19 | Serverwiederherstellung verwendet dieselbe UUID | test_lifecycle.py: Registrierung/Idempotenz, UUID, ETag/PATCH, Archive/Restore; kein Snapshot erzeugt |
| SRV-20 | Globale Serversortierung ist persistent | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| SRV-21 | Gruppensortierung ist persistent | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| SRV-22 | Gruppeninterne Serversortierung ist persistent | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| SRV-23 | Unterschiedliche Gruppensortierungen sind voneinander unabhängig | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| SRV-24 | Inventare verändern keine Sortierpositionen | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| SRV-25 | Inventare verändern keine Gruppenmitgliedschaften | test_security.py: echte technische DB-Logins, verschachtelte normalisierte Inventarfelder, bestehende FK/Snapshot-Guards |
| SRV-26 | Inventare verändern keine Primärgruppen | test_security.py: echte technische DB-Logins, verschachtelte normalisierte Inventarfelder, bestehende FK/Snapshot-Guards |
| SRV-27 | Keine automatische Gruppierung aufgrund von Betriebssystemen | test_security.py: echte technische DB-Logins, verschachtelte normalisierte Inventarfelder, bestehende FK/Snapshot-Guards |
| SRV-28 | Keine automatische Gruppierung aufgrund von CVEs | test_security.py: echte technische DB-Logins, verschachtelte normalisierte Inventarfelder, bestehende FK/Snapshot-Guards |
| SRV-29 | Keine automatische Gruppierung aufgrund von Paketen | test_security.py: echte technische DB-Logins, verschachtelte normalisierte Inventarfelder, bestehende FK/Snapshot-Guards |
| SRV-30 | Keine automatische Gruppierung aufgrund technischer Inventardaten | test_security.py: echte technische DB-Logins, verschachtelte normalisierte Inventarfelder, bestehende FK/Snapshot-Guards |
| SRV-31 | Administrative Änderungen benötigen Dashboard-Authentifizierung | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| SRV-32 | Administrative Änderungen benötigen Funktionsberechtigung | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| SRV-33 | Administrative Änderungen benötigen CSRF-Schutz | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| SRV-34 | Kritische Änderungen benötigen Reauthentifizierung | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| SRV-35 | Technische Upload-Tokens besitzen keine Verwaltungsrechte | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| SRV-36 | User Admin besitzt keine Gruppenverwaltungsrechte | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| SRV-37 | Viewer darf keine Verwaltungsdaten verändern | test_security.py: drei nichtadministrative Rollen, vollständige Session, CSRF/Einmal-Reauth; Authsuite 56 |
| SRV-38 | Serverlisten werden ACL-gefiltert | test_security.py/test_recovery_performance.py: SQL-ACL vor Suche/Pagination/Zählung, BOLA/Mass Assignment negativ |
| SRV-39 | Gruppenlisten geben keine fremden Server preis | test_security.py/test_recovery_performance.py: SQL-ACL vor Suche/Pagination/Zählung, BOLA/Mass Assignment negativ |
| SRV-40 | Keine BOLA-Sicherheitslücken in den getesteten Zugriffspfaden | test_security.py/test_recovery_performance.py: SQL-ACL vor Suche/Pagination/Zählung, BOLA/Mass Assignment negativ |
| SRV-41 | Kein Mass Assignment | test_security.py/test_recovery_performance.py: SQL-ACL vor Suche/Pagination/Zählung, BOLA/Mass Assignment negativ |
| SRV-42 | Versionskonflikte werden erkannt | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| SRV-43 | Konkurrierende Änderungen verletzen keine Integritätsregeln | test_ordering.py/test_recovery_performance.py: drei Kontexte, CAS, relative Moves, Konkurrenz und echte Neustarts |
| SRV-44 | Administrative Datenbankrechte bleiben getrennt | 00016; frische/repetierte Migration, 189 native DB-Tests und tatsächliche Rollenlogins |
| SRV-45 | Fachliche Änderungen und Outbox-Ereignisse sind transaktional konsistent | test_security.py/test_recovery_performance.py: Audit-ID/Digest, gemeinsamer Outbox-Commit, Fault-Rollback, Secret-Scan |
| SRV-46 | Sicherheitsrelevante Änderungen werden auditiert | test_security.py/test_recovery_performance.py: Audit-ID/Digest, gemeinsamer Outbox-Commit, Fault-Rollback, Secret-Scan |
| SRV-47 | PostgreSQL bleibt das einzige Datenbanksystem | 40 Infrastruktur- und 10 Service-Regressionstests; sechs eigene Dienste healthy und interne Backendports |
| SRV-48 | Kein Redis | 40 Infrastruktur- und 10 Service-Regressionstests; sechs eigene Dienste healthy und interne Backendports |
| SRV-49 | Kein zusätzlicher Message Broker | 40 Infrastruktur- und 10 Service-Regressionstests; sechs eigene Dienste healthy und interne Backendports |
| SRV-50 | Keine zusätzliche Workflow-Engine | 40 Infrastruktur- und 10 Service-Regressionstests; sechs eigene Dienste healthy und interne Backendports |
| SRV-51 | Kein automatischer Zugriff auf verwaltete Server | 40 Infrastruktur- und 10 Service-Regressionstests; sechs eigene Dienste healthy und interne Backendports |
| SRV-52 | Kein Docker-Socket | 40 Infrastruktur- und 10 Service-Regressionstests; sechs eigene Dienste healthy und interne Backendports |
| SRV-53 | Keine unnötigen öffentlichen Backend-Ports | 40 Infrastruktur- und 10 Service-Regressionstests; sechs eigene Dienste healthy und interne Backendports |
| SRV-54 | Keine unnötigen privilegierten Container | 40 Infrastruktur- und 10 Service-Regressionstests; sechs eigene Dienste healthy und interne Backendports |
| SRV-55 | Negative Berechtigungs- und Integritätstests sind verpflichtend | Gesamte lokale Testmatrix, End-to-End, Offline-Wheels, Diagnose und verlinkte Dokumentation |

## Schlusskriterien gemäß Abschnitt 31

| Nr. | Kriterium | Ergebnis |
|---|---|---|
| 1 | Administrative Serverregistrierung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 2 | Unveränderliche Server-UUID. | bestanden; oben zugeordnete Tests und Testmatrix |
| 3 | Serverstammdaten. | bestanden; oben zugeordnete Tests und Testmatrix |
| 4 | Serverarchivierung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 5 | Serverwiederherstellung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 6 | Keine automatische Inventarisierung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 7 | Keine automatische Serverregistrierung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 8 | Gruppen erstellen. | bestanden; oben zugeordnete Tests und Testmatrix |
| 9 | Gruppen bearbeiten. | bestanden; oben zugeordnete Tests und Testmatrix |
| 10 | Gruppen archivieren. | bestanden; oben zugeordnete Tests und Testmatrix |
| 11 | Gruppen wiederherstellen. | bestanden; oben zugeordnete Tests und Testmatrix |
| 12 | Keine unkontrollierte Kaskadenlöschung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 13 | Keine automatische Gruppierung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 14 | Mehrfachzuordnung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 15 | Eindeutige Mitgliedschaften. | bestanden; oben zugeordnete Tests und Testmatrix |
| 16 | Genau eine Primärgruppe bei vorhandenen Mitgliedschaften. | bestanden; oben zugeordnete Tests und Testmatrix |
| 17 | Keine Primärgruppe ohne Mitgliedschaft. | bestanden; oben zugeordnete Tests und Testmatrix |
| 18 | Atomare Änderungen. | bestanden; oben zugeordnete Tests und Testmatrix |
| 19 | Konkurrenzsichere Integrität. | bestanden; oben zugeordnete Tests und Testmatrix |
| 20 | Gruppensortierung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 21 | Globale Serversortierung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 22 | Gruppeninterne Serversortierung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 23 | Persistente Positionen. | bestanden; oben zugeordnete Tests und Testmatrix |
| 24 | Keine verlorenen konkurrierenden Änderungen. | bestanden; oben zugeordnete Tests und Testmatrix |
| 25 | Kein Einfluss technischer Inventare. | bestanden; oben zugeordnete Tests und Testmatrix |
| 26 | RBAC. | bestanden; oben zugeordnete Tests und Testmatrix |
| 27 | Server-ACL. | bestanden; oben zugeordnete Tests und Testmatrix |
| 28 | CSRF. | bestanden; oben zugeordnete Tests und Testmatrix |
| 29 | Reauthentifizierung. | bestanden; oben zugeordnete Tests und Testmatrix |
| 30 | Keine administrativen Uploadrechte. | bestanden; oben zugeordnete Tests und Testmatrix |
| 31 | Keine unzulässigen Objektzugriffe. | bestanden; oben zugeordnete Tests und Testmatrix |
| 32 | Keine Mass-Assignment-Lücken. | bestanden; oben zugeordnete Tests und Testmatrix |
| 33 | Versionierte Migrationen. | bestanden; oben zugeordnete Tests und Testmatrix |
| 34 | Geeignete Constraints. | bestanden; oben zugeordnete Tests und Testmatrix |
| 35 | Geeignete Indizes. | bestanden; oben zugeordnete Tests und Testmatrix |
| 36 | Transaktionssicherheit. | bestanden; oben zugeordnete Tests und Testmatrix |
| 37 | Getrennte administrative und technische Schreibrechte. | bestanden; oben zugeordnete Tests und Testmatrix |
| 38 | Audit. | bestanden; oben zugeordnete Tests und Testmatrix |
| 39 | Transactional Outbox. | bestanden; oben zugeordnete Tests und Testmatrix |
| 40 | Unit-Tests. | bestanden; oben zugeordnete Tests und Testmatrix |
| 41 | PostgreSQL-Integrationstests. | bestanden; oben zugeordnete Tests und Testmatrix |
| 42 | API-Integrationstests. | bestanden; oben zugeordnete Tests und Testmatrix |
| 43 | Sicherheitstests. | bestanden; oben zugeordnete Tests und Testmatrix |
| 44 | Konkurrenztests. | bestanden; oben zugeordnete Tests und Testmatrix |
| 45 | Persistenztests. | bestanden; oben zugeordnete Tests und Testmatrix |
| 46 | Dokumentation. | bestanden; oben zugeordnete Tests und Testmatrix |
| 47 | Übergabe an Phase 11. | bestanden; oben zugeordnete Tests und Testmatrix |

## Auswirkungen auf vorherige Phasen

Phase-8-Resolver bietet eine eingeschränkte Projektion für den separaten Administrationspool;
keine Passwordhash-/MFA-Geheimnisrechte für dashboard_admin. Die vollständige Authsuite besteht.
Phase-9-Principal verwendet dieselbe eingeschränkte Projektion. Berechtigungs-/Rollenmatrix,
ACL-Grundsätze und native Letzter-Admin-Invariante bleiben erhalten; 37 RBAC-Tests bestehen.
Drei alte Testfixtures wählen ihre Primärgruppe jetzt ausdrücklich, statt einen künftig
ungültigen Datenzustand zu committen. Der frühere Deploymenttest erwartet für die nun
implementierten Server-/Gruppenrouten ohne Cookie 401. Alte Phasenverträge bleiben unverändert.

Die bestehende Nginx-Grenze leitet nur bekannte Dashboardrouten über das private Gate;
Backendports, Sicherheitsoptionen, TLS-/Egress-/Mailgrenzen bleiben geprüft. PostgreSQL-
Berechtigungen für technische Inventar-/CVE-/Matching-/Dispatcherrollen bleiben eingeschränkt.
Vorhandenes administration.changed-Event mit seiner ursprünglichen Quelle wiederverwendet.

## Betrieb und Grenzen

Sechs eigene Dienste healthy, API 0.10.0 und Revision 00016 aktiv. Vier fremde Nextcloud-
Container unverändert. Dashboard-Verwaltung ohne Cookie 401, technische Domain 403.
Keine produktiven Benutzer, Server, Gruppen oder Mitgliedschaften angelegt; kein automatischer
Administrator. Dispatcherziele weiterhin leer. Keine Hostfirewall-/fremden Volumenänderungen.
Schreibgeschützte Diagnosewerkzeuge bestätigen Schema, Mitgliedschaften, Positionen und Rechte.

Globale Schreibserialisierung und O(N)-Bulk-Sortierung sind bewusste erste Implementierung;
repräsentative Last ist lokal geprüft, größere Produktionsbestände bleiben Phase 23.
Native Constraints schützen persistente Datenintegrität. Operatoren mit Host-/Ownerrechten
bleiben Vertrauensgrenze und benötigen bei Reparaturen ein explizites Backup-/Freigabeverfahren.
Keine öffentliche Reparaturroute, automatische Gruppierung oder technische Serververbindung.
UI, tatsächliche Inventarannahme und Benachrichtigungen folgen ihren vorgesehenen Phasen.
Gehostete CI, Commit und Push nicht ausgeführt; lokale CI-Prüfungen bestanden.

Rohprotokolle lokal unter .runtime/test-reports/phase-10-*.log/json, ignoriert und auf 0600 begrenzt.
