# Phase-9-Abnahme

Stand: 06.11.2026. **Status: completed — alle 45 Aufträge, 66 Pflichtprüfungen,
50 RBAC-Invarianten und 45 Schlusskriterien lokal erfüllt.**

863 verschiedene Tests bestanden: 389 Standardtests (einschließlich 45 neuer RBAC-Unit-Tests),
37 neue Autorisierungs-Integrationstests, 56 Authentifizierungs-, 29 Job-/Outbox-,
10 Service-, 189 PostgreSQL-, 40 Infrastruktur-, 77 Envoy- und 36 Postfix-Tests.
Die Standardauswahl schließt die gesonderten Docker-Integrationssuiten aus; keine doppelte Zählung.
Keine verpflichtende lokale Prüfung ausgelassen.

API 0.9.0; common/Dispatcher weiterhin 0.7.0. Additive Revision 00015 auf frischer und
bestehender Datenbank geprüft, wiederholte Migration ohne weitere Änderung. Vorhandene
14 Migrationen, Originalkonzepte, ältere Verträge und externe Abhängigkeiten unverändert.
make check, setup/python-check, Ruff/Format und Mypy (224 Quelldateien) erfolgreich.
Secret-Baseline unverändert. Frische Offline-Installation aus Hash-geprüften Runtime-Wheels
plus lokalen Projektwheels, pip check, isolierte Imports ohne Netzwerk und Paketressourcen geprüft.

[45 Aufgaben](phase-09-status.md), [Dateimanifest](phase-09-files.json),
[Testmatrix](../testing/phase-09-test-matrix.md), [Performancenachweis](../testing/phase-09-performance.md),
[Übergabe](phase-09-handover.md).

## Verpflichtende Prüfungen T09.09.05

Alle Zeilen erfolgreich. Testdateien beziehen sich auf tests/authorization/integration/,
Unit-Tests auf tests/authorization/unit/.

| Nr. | Vorgabe | Nachweis |
|---|---|---|
| 1 | Bestehende Security-Tabellen wiederverwendet. | Migration 00015; native DB-/Privilegientests und 189 DB-Regressionstests |
| 2 | Datenbankmigrationen versioniert. | Migration 00015; native DB-/Privilegientests und 189 DB-Regressionstests |
| 3 | Datenbankrollen korrekt. | Migration 00015; native DB-/Privilegientests und 189 DB-Regressionstests |
| 4 | Keine PostgreSQL-Superuser-Rechte. | Migration 00015; native DB-/Privilegientests und 189 DB-Regressionstests |
| 5 | Benutzeranlage funktioniert. | test_administration.py / test_recovery.py; echter HTTPS-Lebenszyklus, Aktivierung und Widerruf |
| 6 | Benutzerlisten funktionieren. | test_administration.py / test_recovery.py; echter HTTPS-Lebenszyklus, Aktivierung und Widerruf |
| 7 | Benutzeränderungen funktionieren. | test_administration.py / test_recovery.py; echter HTTPS-Lebenszyklus, Aktivierung und Widerruf |
| 8 | Benutzerdeaktivierung funktioniert. | test_administration.py / test_recovery.py; echter HTTPS-Lebenszyklus, Aktivierung und Widerruf |
| 9 | Benutzerarchivierung funktioniert. | test_administration.py / test_recovery.py; echter HTTPS-Lebenszyklus, Aktivierung und Widerruf |
| 10 | Sessions werden bei Deaktivierung widerrufen. | test_administration.py / test_recovery.py; echter HTTPS-Lebenszyklus, Aktivierung und Widerruf |
| 11 | Vier Systemrollen vorhanden. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 12 | Systemrollen geschützt. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 13 | Berechtigungskatalog vorhanden. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 14 | Rollenmatrix korrekt. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 15 | Effektive Rollenrechte korrekt. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 16 | Zusätzliche Rollen eingeschränkt. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 17 | Rollenvergabe geschützt. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 18 | Rollenentzug geschützt. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 19 | Keine Selbsteskalation. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 20 | User Admin kann Administratorrollen nicht verändern. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 21 | Default Deny funktioniert. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 22 | Zentrale Autorisierungsengine funktioniert. | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| 23 | Objektbezogene Server-ACL funktioniert. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 24 | ACL-Vergabe geschützt. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 25 | ACL-Entzug geschützt. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 26 | Nicht berechtigte Server nicht sichtbar. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 27 | Serverlisten korrekt gefiltert. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 28 | Suchabfragen korrekt gefiltert. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 29 | Pagination korrekt gefiltert. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 30 | Aggregationen korrekt gefiltert. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 31 | Gruppenmitgliedschaften verleihen keine automatischen Rechte. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 32 | Primärgruppen verleihen keine automatischen Rechte. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 33 | Dashboard-Uploadberechtigung getrennt. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 34 | Technischer API-Upload getrennt. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 35 | Keine Uploadrechte auf Gruppenverwaltung. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 36 | Keine Uploadrechte auf manuelle Sortierung. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 37 | Administrative Gruppenrechte geschützt. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 38 | Administrative Sortierrechte geschützt. | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| 39 | Letzter Administrator geschützt. | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| 40 | Parallele Administratoränderungen sicher. | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| 41 | Administrative Reauthentifizierung funktioniert. | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| 42 | MFA-Recovery geschützt. | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| 43 | User Admin kann Administrator-MFA nicht zurücksetzen. | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| 44 | Rechteentzug wirkt auf aktive Sessions. | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| 45 | Keine unkontrollierten Berechtigungscaches. | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| 46 | CSRF-Schutz für Verwaltungsoperationen. | test_administration.py / test_deployment.py; Session/CSRF/Headers, BOLA, strikt validierte Felder |
| 47 | Keine Manipulation durch Client-Header. | test_administration.py / test_deployment.py; Session/CSRF/Headers, BOLA, strikt validierte Felder |
| 48 | Kein Mass Assignment. | test_administration.py / test_deployment.py; Session/CSRF/Headers, BOLA, strikt validierte Felder |
| 49 | Keine BOLA-Sicherheitslücke in den getesteten Pfaden. | test_administration.py / test_deployment.py; Session/CSRF/Headers, BOLA, strikt validierte Felder |
| 50 | Keine vertikale Rechteeskalation. | test_administration.py / test_deployment.py; Session/CSRF/Headers, BOLA, strikt validierte Felder |
| 51 | Keine horizontale Rechteeskalation. | test_administration.py / test_deployment.py; Session/CSRF/Headers, BOLA, strikt validierte Felder |
| 52 | Audit-Ereignisse vorhanden. | test_audit.py; atomarer Audit/Outbox-Commit und Rollback; eingeschränkte Antwortfelder; Secret-Scan |
| 53 | Transactional Outbox integriert. | test_audit.py; atomarer Audit/Outbox-Commit und Rollback; eingeschränkte Antwortfelder; Secret-Scan |
| 54 | Keine Secrets in Logs. | test_audit.py; atomarer Audit/Outbox-Commit und Rollback; eingeschränkte Antwortfelder; Secret-Scan |
| 55 | Keine sensiblen Credentials in API-Antworten. | test_audit.py; atomarer Audit/Outbox-Commit und Rollback; eingeschränkte Antwortfelder; Secret-Scan |
| 56 | Keine unnötigen öffentlichen Ports. | test_deployment.py; 40 Infrastruktur- und 10 Service-Regressionstests; privates Backend |
| 57 | Kein Docker-Socket. | test_deployment.py; 40 Infrastruktur- und 10 Service-Regressionstests; privates Backend |
| 58 | Keine unnötigen Containerprivilegien. | test_deployment.py; 40 Infrastruktur- und 10 Service-Regressionstests; privates Backend |
| 59 | Unit-Tests erfolgreich. | Lokale Testläufe und nachfolgende Betriebs-/Dokumentationsnachweise; Übergabevertrag |
| 60 | Integrationstests erfolgreich. | Lokale Testläufe und nachfolgende Betriebs-/Dokumentationsnachweise; Übergabevertrag |
| 61 | Sicherheitstests erfolgreich. | Lokale Testläufe und nachfolgende Betriebs-/Dokumentationsnachweise; Übergabevertrag |
| 62 | Konkurrenztests erfolgreich. | Lokale Testläufe und nachfolgende Betriebs-/Dokumentationsnachweise; Übergabevertrag |
| 63 | Dokumentation vollständig. | Lokale Testläufe und nachfolgende Betriebs-/Dokumentationsnachweise; Übergabevertrag |
| 64 | Übergabe an Phase 10 vorbereitet. | Lokale Testläufe und nachfolgende Betriebs-/Dokumentationsnachweise; Übergabevertrag |
| 65 | Keine Fachfunktionen späterer Phasen vorzeitig implementiert. | Lokale Testläufe und nachfolgende Betriebs-/Dokumentationsnachweise; Übergabevertrag |
| 66 | Keine unzulässigen Architekturänderungen. | Lokale Testläufe und nachfolgende Betriebs-/Dokumentationsnachweise; Übergabevertrag |

## Sicherheitsinvarianten

Alle 50 Regeln im lokalen implementierten Umfang erfüllt. Noch nicht veröffentlichte
Fachmutationen sind durch Default Deny und fehlende Routen gesperrt; ihre spätere
Implementierung muss die vorbereiteten Gruppen-/Sortier-/Maschinenrechte erneut prüfen.

| ID | Regel | Nachweis |
|---|---|---|
| RBAC-01 | Jede geschützte Operation benötigt eine positive Berechtigungsentscheidung | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| RBAC-02 | Default Deny | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| RBAC-03 | Rollenrechte werden serverseitig ermittelt | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| RBAC-04 | Keine Rollen aus unkontrollierten Request-Headern | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| RBAC-05 | Keine Rechtevergabe durch unvalidierte Eingabefelder | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| RBAC-06 | Kein Mass Assignment | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| RBAC-07 | Keine Selbsteskalation | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| RBAC-08 | Systemrollen sind gegen gewöhnliche Änderungen geschützt | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| RBAC-09 | User Admin darf keine Administratorrechte vergeben | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| RBAC-10 | User Admin darf keine Administratorkonten deaktivieren | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| RBAC-11 | User Admin darf keine administrative MFA zurücksetzen | 45 Unit-Tests; test_administration.py / test_concurrency.py; endliche Matrix, Systemrollenschutz, Delegation |
| RBAC-12 | Objektberechtigungen verwenden die unveränderliche Server-UUID | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-13 | Ein Rollenrecht allein erlaubt keinen Zugriff auf alle Server | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-14 | Nicht freigegebene Server sind nicht sichtbar | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-15 | Listenabfragen werden serverseitig autorisiert | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-16 | Suchabfragen werden serverseitig autorisiert | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-17 | Pagination berücksichtigt ACLs | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-18 | Aggregationen berücksichtigen ACLs | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-19 | Gruppenmitgliedschaften verleihen nicht automatisch Serverrechte | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-20 | Primärgruppen verleihen nicht automatisch Serverrechte | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-21 | Mehrfachgruppenzugehörigkeit verändert keine ACL | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-22 | Dashboard-Upload benötigt separate Berechtigung | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-23 | Dashboard-Upload benötigt Serverfreigabe | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-24 | Technischer API-Upload verwendet keine Browser-Session | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-25 | Technische API-Tokens besitzen keine administrativen Gruppenrechte | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-26 | Inventarverarbeitung verändert keine Gruppenmitgliedschaften | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-27 | Inventarverarbeitung verändert keine Primärgruppen | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-28 | Inventarverarbeitung verändert keine manuelle Sortierung | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-29 | Gruppenänderungen ausschließlich über geschützte Dashboard-Administrationsfunktionen | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-30 | Manuelle Sortierungen ausschließlich über geschützte Dashboard-Administrationsfunktionen | test_objects.py / test_performance.py; ACL vor Suche/Pagination/Aggregation; Phase-10/11-Schreibpfade unveröffentlicht |
| RBAC-31 | Der letzte nutzbare Administrator bleibt geschützt | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| RBAC-32 | Parallele administrative Änderungen umgehen den Administratorschutz nicht | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| RBAC-33 | Kritische Administratoraktionen benötigen aktuelle Reauthentifizierung | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| RBAC-34 | Administrator-MFA-Recovery ist besonders geschützt | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| RBAC-35 | Rechteentzug muss unmittelbar wirksam werden | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| RBAC-36 | Deaktivierte Benutzer verlieren ihren aktiven Zugang | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| RBAC-37 | Berechtigungscaches dürfen einen Widerruf nicht umgehen | test_concurrency.py / test_recovery.py; native Status-/Rollen-/Credential-/MFA-Guards, Reauth/Widerruf |
| RBAC-38 | Administrative Änderungen werden auditiert | test_audit.py; atomarer Audit/Outbox-Commit und Rollback; eingeschränkte Antwortfelder; Secret-Scan |
| RBAC-39 | Sicherheitsereignisse enthalten keine Secrets | test_audit.py; atomarer Audit/Outbox-Commit und Rollback; eingeschränkte Antwortfelder; Secret-Scan |
| RBAC-40 | PostgreSQL bleibt das einzige Datenbanksystem | test_deployment.py; 40 Infrastruktur- und 10 Service-Regressionstests; privates Backend |
| RBAC-41 | Kein Redis | test_deployment.py; 40 Infrastruktur- und 10 Service-Regressionstests; privates Backend |
| RBAC-42 | Kein zusätzlicher Message Broker | test_deployment.py; 40 Infrastruktur- und 10 Service-Regressionstests; privates Backend |
| RBAC-43 | Keine PostgreSQL-Superuser-Rechte für reguläre Dienste | test_deployment.py; 40 Infrastruktur- und 10 Service-Regressionstests; privates Backend |
| RBAC-44 | Keine unnötigen öffentlichen Backend-Ports | test_deployment.py; 40 Infrastruktur- und 10 Service-Regressionstests; privates Backend |
| RBAC-45 | Kein Docker-Socket | test_deployment.py; 40 Infrastruktur- und 10 Service-Regressionstests; privates Backend |
| RBAC-46 | Keine unnötigen Containerprivilegien | test_deployment.py; 40 Infrastruktur- und 10 Service-Regressionstests; privates Backend |
| RBAC-47 | Berechtigungsprüfungen werden negativ getestet | test_administration.py / test_deployment.py; Session/CSRF/Headers, BOLA, strikt validierte Felder |
| RBAC-48 | Nicht authentifizierte Benutzer erhalten keine Verwaltungsrechte | test_administration.py / test_deployment.py; Session/CSRF/Headers, BOLA, strikt validierte Felder |
| RBAC-49 | Unvollständige MFA gewährt keine Administrationsrechte | test_administration.py / test_deployment.py; Session/CSRF/Headers, BOLA, strikt validierte Felder |
| RBAC-50 | Technische Maschinenidentitäten bleiben von menschlichen Rollen getrennt | test_administration.py / test_deployment.py; Session/CSRF/Headers, BOLA, strikt validierte Felder |

## Abschließende Phasenabnahme gemäß Abschnitt 31

| Nr. | Kriterium | Ergebnis |
|---|---|---|
| 1 | Benutzeranlage. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 2 | Benutzerlisten. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 3 | Benutzerbearbeitung. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 4 | Aktivierung. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 5 | Deaktivierung. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 6 | Archivierung. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 7 | Sessionwiderruf. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 8 | Vier Systemrollen. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 9 | Berechtigungskatalog. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 10 | Rollenmatrix. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 11 | Eingeschränkte zusätzliche Rollen. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 12 | Kontrollierte Rollenvergabe. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 13 | Kontrollierter Rollenentzug. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 14 | Keine Selbsteskalation. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 15 | Server-ACL. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 16 | Server-UUID. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 17 | ACL-Vergabe. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 18 | ACL-Widerruf. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 19 | Sichere Serverlisten. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 20 | Sichere Suchabfragen. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 21 | Sichere Pagination. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 22 | Sichere Aggregationen. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 23 | Gruppenrechte getrennt. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 24 | Sortierrechte getrennt. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 25 | Dashboard-Uploadrechte getrennt. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 26 | Technische Uploadidentitäten getrennt. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 27 | Keine Upload-basierten Gruppenänderungen. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 28 | Keine automatische ACL-Vererbung aus Gruppen. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 29 | Letzter Administrator geschützt. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 30 | Parallele Änderungen sicher. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 31 | MFA-Pflicht. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 32 | Reauthentifizierung. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 33 | Administrative Recovery abgesichert. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 34 | Kritische Rechteänderungen werden unmittelbar wirksam. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 35 | FastAPI-Integration. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 36 | CSRF-Schutz. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 37 | Audit. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 38 | Transactional Outbox. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 39 | Datenbankrechte. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 40 | Unit-Tests. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 41 | Integrationstests. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 42 | Sicherheitstests. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 43 | Konkurrenztests. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 44 | Dokumentation. | bestanden; Testmatrix und oben zugeordnete Nachweise |
| 45 | Übergabe an Phase 10. | bestanden; Testmatrix und oben zugeordnete Nachweise |

## Betrieb und praktische Grenzen

Sechs eigene Dienste healthy; API 0.9.0 und Datenbankrevision 00015 aktiv. Vier fremde
Nextcloud-Container bleiben unverändert. Dashboard-Verwaltung ohne Cookie liefert 401,
separate technische API-Domain 403; unveröffentlichte Serververwaltung 403. Keine
produktiven Benutzer, Credentials, Sessions, MFA-Faktoren oder Server-ACLs angelegt.
Vier exakte Systemrollen geprüft; erster Administrator bleibt kontrollierter Phase-8-Bootstrap
(invariant_armed=false, usable_administrators=0). Kein automatisches Notfallkonto.
Dispatcher-Zustellziele bleiben leer. Hostfirewall und fremde Volumes bleiben unberührt.

Native Letzter-Admin-Prüfung schützt den persistenten nutzbaren Credential-/Faktorstatus.
Tatsächlicher Faktor-/Schlüsselbesitz und unabhängige Recovery-Identitätsprüfung bleiben
Betriebsverantwortung. Aktivierungs-/Recovery-Handoff ist manuell über neue private 0600-Dateien;
automatische Zustellung folgt Phase 19. Benutzeroberfläche und Server-/Gruppenmutationen
folgen ihren geplanten Phasen. Lastmessungen sind lokale Baselines, kein Produktions-SLA.
Gehostete CI, Commit und Push wurden nicht ausgeführt; lokale CI-Prüfungen sind bestanden.

Lokale Rohprotokolle und Performance-JSON unter .runtime/test-reports/phase-09-*.
