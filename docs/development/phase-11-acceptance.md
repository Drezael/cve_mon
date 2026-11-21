# Phase-11-Abnahme

Stand: 07.11.2026. **Status: completed — alle 45 Aufträge, 95 Pflichtprüfungen,
61 INVUP-Invarianten und 61 Schlusskriterien lokal nachgewiesen.**

1089 verschiedene Tests bestanden: 500 Standardtests einschließlich 55 neuer Upload-
Unit-/Vertragstests; 62 neue Upload-Integrationstests; 53 Serververwaltungs-, 37 Autorisierungs-,
56 Authentifizierungs-, 29 Job-/Outbox-, 10 Service-, 189 PostgreSQL-, 40 Infrastruktur-,
77 Envoy- und 36 Postfix-Tests. Standardauswahl und Docker-Suiten überschneiden sich nicht.

make check: Ruff/Format, Mypy (284 Quelldateien), 500 Tests, Struktur/JSON/Schema/OpenAPI,
22 YAML-Dateien, beide Compose-Modelle und Secret-Scan erfolgreich. Kein verpflichtender
lokaler Nachweis ausgelassen. Remote-CI wurde nicht ausgeführt; ihr Uploadziel ist ergänzt.

API 0.11.0 aus finalem Wheel gebaut und aktiv; common und Dispatcher unverändert 0.7.0.
Frische Offline-venv aus hashgeprüften Runtime-Wheels, pip check, isolierte Imports ohne
Netzwerk und vollständiger Quell-/Wheelvergleich erfolgreich. Runtime ergänzt JSON Schema,
rfc3339-validator und python-multipart, alle exakt/hashgesichert. Kein Dependency-Update
außerhalb dieser Annahmevoraussetzungen. Originalschema und sechs Beispiele unverändert.

Additive Revision 00017 auf frischer und bestehender Datenbank sowie wiederholte Migration
erfolgreich. Die 189 DB-Tests prüfen auch isolierten Restore; der neue Uploadtest sichert und
restauriert zusätzlich einen tatsächlich angenommenen Payload samt Provenienz und nativen
Quotazählern. Ältere 16 Migrationen, ursprüngliche Konzepte/Verträge und Secretbaseline
unverändert. [Dateimanifest](phase-11-files.json) dokumentiert Ergänzungen und Änderungen.

Live: sechs eigene Dienste healthy, Revision 00017. Keine Benutzer, Server, Gruppen,
Clients, Zertifikate, Tokens, Annahmen, Snapshots oder Jobs aus Testfixtures im Entwicklungs-
deployment. Keine automatische Administratoranlage. Technischer Zugang ohne Zertifikat 403,
mit gültigem Zertifikat ohne Bearer 401; Dashboardstatus ohne Session 401; Upload auf API-
Domain 404. Keine zusätzlichen Ports, Dienste, Docker-Sockets oder Containerprivilegien.
Vier fremde Nextcloud-Container mit unveränderten IDs; Hostfirewall unverändert.

Technischer und Dashboard-Ende-zu-Ende-Upload über echtes HTTPS/Nginx, Browser-MFA,
API-/PostgreSQL-Neustart und Datenbankausfall geprüft. Parallele Idempotenz durch unabhängige
DB-Transaktionen, Commitzeit-Widerruf von Token/ACL/Server, Auditrollback und verlorene
Commitbestätigung geprüft. Kein Test verlässt eigene UUID-isolierte Projekte.

HTTP 202 bedeutet ausschließlich persistentes accepted nach Commit, auch für Retries.
Keine vorgetäuschte Verarbeitung, keine Snapshots oder unregistrierten Phase-14-Jobs.
Die neue Version konkretisiert den früheren Snapshot-/Job-/200-Plan ausdrücklich in
[ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md).

Ressourcen: 10 MiB Originaldatei, 1 MiB Multipartrahmen, ein begrenzter Parserprozess,
256 MiB Adressraum/12 CPU-/15 Walltime-Sekunden, API 512 MiB. Persistente Minutenlimits,
native 100 Annahmen/Server, 10000 gesamt und 1 GiB Originalbytes; JSONB/Index/WAL benötigen
zusätzlichen Platz. Keine automatische Retention. Lokale CRL gültig bis 14.11.2026;
Produktions-CA/CRL und kontrollierte Secret-/Credentialprovisionierung sind Betreiberaufgaben.
[Performance](../testing/phase-11-performance.md), [Betrieb](../operations/inventory-upload.md),
[Übergabe an 12/13/14](phase-11-handover.md). Keine automatische Folgephase gestartet.

## 95 verpflichtende Prüfungen

| Nr. | Kriterium | Nachweis — bestanden |
|---|---|---|
| 1 | Vorhandene Architektur berücksichtigt. | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| 2 | Beide Uploadwege implementiert. | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| 3 | Gemeinsamer Annahmeservice vorhanden. | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| 4 | Verbindliches JSON-Schema wird verwendet. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 5 | Schema-Versionierung funktioniert. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 6 | Keine widersprüchlichen Inventarformate. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 7 | Technischer mTLS-Zugang vorhanden. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 8 | Clientzertifikat verpflichtend. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 9 | Zertifikatskette wird geprüft. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 10 | Zertifikatsablauf wird geprüft. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 11 | Zertifikatswiderruf berücksichtigt. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 12 | Nginx-zu-API-Vertrauensgrenze abgesichert. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 13 | Manipulierte Zertifikatsheader wirkungslos. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 14 | Technische Clientregistrierung funktioniert. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 15 | Technische API-Tokens können ausgestellt werden. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 16 | Tokens werden geschützt gespeichert. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 17 | Tokens werden nur einmal im Klartext ausgegeben. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 18 | Tokenrotation funktioniert. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 19 | Tokenwiderruf funktioniert. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 20 | Scope `inventory:submit` wird geprüft. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 21 | Token an registrierten Server gebunden. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 22 | Token an zugelassene Zertifikatsidentität gebunden. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 23 | Keine technische Autorisierung über Browser-Session. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 24 | Technischer Upload-Endpunkt funktioniert. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 25 | Technischer Upload akzeptiert nur gültiges JSON. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 26 | Manueller Dashboard-Upload funktioniert. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 27 | Dashboard-Session wird geprüft. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 28 | MFA-Anforderungen werden berücksichtigt. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 29 | CSRF funktioniert. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 30 | `inventory:upload:dashboard` wird geprüft. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 31 | Server-ACL wird geprüft. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 32 | Keine Dashboard-Autorisierung durch technisches Token. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 33 | Unbekannter Server wird abgelehnt. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 34 | Archivierter Server wird abgelehnt. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 35 | Server-UUID im Inventar wird geprüft. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 36 | Falsche Server-UUID wird abgelehnt. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 37 | JSON-Schema-Prüfung funktioniert. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 38 | Unbekannte Schema-Version wird abgelehnt. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 39 | Fehlende Pflichtfelder werden abgelehnt. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 40 | Unbekannte strukturierte Felder werden abgelehnt. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 41 | Administrative Gruppenfelder werden abgelehnt. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 42 | Administrative Primärgruppenfelder werden abgelehnt. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 43 | Administrative Sortierfelder werden abgelehnt. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 44 | Ungültige JSON-Syntax wird abgelehnt. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 45 | Doppelte JSON-Schlüssel werden abgelehnt. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 46 | Nicht standardkonforme JSON-Werte werden abgelehnt. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 47 | UTF-8-Validierung funktioniert. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 48 | Größenlimits funktionieren. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 49 | Parser-Ressourcenlimits funktionieren. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 50 | Multipart-Limits funktionieren. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 51 | Dateinamen werden nicht als lokale Pfade verwendet. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 52 | Temporäre Dateien werden bereinigt. | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| 53 | Persistente Annahmespeicherung funktioniert. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 54 | Submission-ID eindeutig. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 55 | Payload-Hash korrekt. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 56 | Herkunftsdaten korrekt. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 57 | Ursprünglicher Payload gegen unzulässige Änderungen geschützt. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 58 | Idempotenz funktioniert. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 59 | Parallele Idempotenz funktioniert. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 60 | Unterschiedlicher Inhalt bei gleichem Schlüssel wird abgelehnt. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 61 | Kein Datenverlust bei regulären Wiederholungen. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 62 | HTTP 202 erst nach erfolgreichem Commit. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 63 | Keine vorgetäuschte fachliche Verarbeitung. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 64 | Statusabfrage funktioniert. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 65 | Fremde Statusabfragen werden abgelehnt. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 66 | Keine unregistrierten Phase-14-Jobs werden ausgeführt. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 67 | Keine automatische Serverregistrierung. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 68 | Keine automatischen Gruppenänderungen. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 69 | Keine automatischen Primärgruppenänderungen. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 70 | Keine automatischen Sortieränderungen. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 71 | Technische Datenbankrolle besitzt keine administrativen Gruppenrechte. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 72 | Administrative Serverstammdaten bleiben unverändert. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 73 | Audit funktioniert. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 74 | Transactional Outbox funktioniert. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 75 | Keine Secrets in Logs. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 76 | Keine Tokens in HTTP-Antworten außer bei einmaliger autorisierter Ausstellung. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 77 | Keine privaten Schlüssel in Datenbank oder API-Container. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 78 | Keine unnötigen öffentlichen Backendports. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 79 | Kein Docker-Socket. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 80 | Keine unnötigen Containerprivilegien. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 81 | Unit-Tests erfolgreich. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 82 | PostgreSQL-Integrationstests erfolgreich. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 83 | mTLS-Integrationstests erfolgreich. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 84 | Dashboard-Integrationstests erfolgreich. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 85 | Sicherheitstests erfolgreich. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 86 | Konkurrenztests erfolgreich. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 87 | Ausfall- und Recovery-Tests erfolgreich. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 88 | Ende-zu-Ende-Test technisch erfolgreich. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 89 | Ende-zu-Ende-Test Dashboard erfolgreich. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 90 | Dokumentation vollständig. | [Übergabe](phase-11-handover.md), neue API-Verträge, unverändertes Inventarformat 1.0 |
| 91 | Übergabe an Phase 12 vorbereitet. | [Übergabe](phase-11-handover.md), neue API-Verträge, unverändertes Inventarformat 1.0 |
| 92 | Übergabe an Phase 13 vorbereitet. | [Übergabe](phase-11-handover.md), neue API-Verträge, unverändertes Inventarformat 1.0 |
| 93 | Übergabevertrag für Phase 14 dokumentiert. | [Übergabe](phase-11-handover.md), neue API-Verträge, unverändertes Inventarformat 1.0 |
| 94 | Keine Fachfunktionen späterer Phasen vorzeitig implementiert. | [Übergabe](phase-11-handover.md), neue API-Verträge, unverändertes Inventarformat 1.0 |
| 95 | Keine unzulässigen Architekturänderungen. | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |

## 61 Invarianten

| ID | Invariante | Nachweis — bestanden |
|---|---|---|
| INVUP-01 | Zwei getrennte Uploadwege | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| INVUP-02 | Beide Uploadwege verwenden denselben fachlichen Inventarvertrag | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| INVUP-03 | Beide Uploadwege verwenden denselben Annahmeservice | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| INVUP-04 | Technischer Upload verlangt mTLS | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| INVUP-05 | Technischer Upload verlangt gültiges API-Token | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| INVUP-06 | Technischer Upload verlangt `inventory:submit` | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| INVUP-07 | Technisches Token ist an einen Server gebunden | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| INVUP-08 | Token und Zertifikat müssen zur gleichen technischen Identität passen | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| INVUP-09 | Kein Vertrauen in clientseitig gefälschte Zertifikatsheader | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| INVUP-10 | Token können widerrufen werden | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| INVUP-11 | Zertifikate können gesperrt werden | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| INVUP-12 | Keine Klartext-Tokens in PostgreSQL | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| INVUP-13 | Keine privaten Client-Schlüssel in der Plattform-API | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| INVUP-14 | Dashboard-Upload verlangt vollständige Session | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| INVUP-15 | Dashboard-Upload verlangt CSRF | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| INVUP-16 | Dashboard-Upload verlangt `inventory:upload:dashboard` | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| INVUP-17 | Dashboard-Upload verlangt die passende Server-ACL | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| INVUP-18 | Technische Tokens ersetzen keine Browser-Session | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| INVUP-19 | Browser-Sessions ersetzen keine technischen Tokens | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| INVUP-20 | Inventarserver müssen vorregistriert sein | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-21 | Ein unbekannter Server wird nicht automatisch angelegt | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-22 | Ein archivierter Server darf keine neuen Inventare annehmen | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-23 | Payload-UUID muss zum autorisierten Server passen | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-24 | Inventare werden gegen ein versioniertes JSON-Schema validiert | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| INVUP-25 | Unbekannte Schema-Versionen werden abgelehnt | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| INVUP-26 | Administrative Steuerfelder werden abgelehnt | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| INVUP-27 | Keine Gruppenänderung durch Inventar-Upload | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-28 | Keine Primärgruppenänderung durch Inventar-Upload | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-29 | Keine manuelle Sortieränderung durch Inventar-Upload | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-30 | Keine administrative Kritikalitätsänderung durch Inventar-Upload | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-31 | Keine administrative Expositionsänderung durch Inventar-Upload | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-32 | Keine automatische Serverregistrierung durch Inventardaten | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-33 | Uploadgrößen sind begrenzt | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| INVUP-34 | JSON-Parserressourcen sind begrenzt | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| INVUP-35 | Dateinamen werden nicht als unkontrollierte Speicherpfade verwendet | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| INVUP-36 | Keine beliebigen ausführbaren Uploadformate | tests/inventory_upload/unit/test_parser.py und test_boundaries.py; beide Uploadwege |
| INVUP-37 | Angenommene Inventare werden persistent gespeichert | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-38 | Ursprüngliche Annahmedaten werden nicht unkontrolliert überschrieben | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-39 | Jede Einlieferung erhält eine eindeutige Submission-ID | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-40 | Inhalts-Hash wird gespeichert | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-41 | Provenienz wird aus geprüfter Identität abgeleitet | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-42 | Idempotente Wiederholungen sind möglich | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| INVUP-43 | Parallele Duplikate werden konsistent behandelt | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| INVUP-44 | HTTP 202 erfolgt erst nach erfolgreichem Commit | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| INVUP-45 | HTTP 202 bedeutet nicht abgeschlossene Fachverarbeitung | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| INVUP-46 | Keine Verarbeitung durch nicht registrierte Jobhandler | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| INVUP-47 | Statusabfragen sind autorisiert | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-48 | Fremde Submission-Daten bleiben geschützt | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-49 | Technische Datenbankrollen besitzen keine administrativen Gruppenschreibrechte | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-50 | PostgreSQL bleibt das einzige Datenbanksystem | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| INVUP-51 | Kein Redis | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| INVUP-52 | Kein zusätzlicher Message Broker | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| INVUP-53 | Keine zusätzliche Workflow-Engine | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| INVUP-54 | Keine direkten Verbindungen zu verwalteten Servern | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| INVUP-55 | Keine Änderungen am externen Ansible-Repository in Phase 11 | Bestandsanalyse (nur lokal archiviert), [ADR-0029](../architecture/decisions/ADR-0029-inventory-acceptance-phase11.md) |
| INVUP-56 | Audit für relevante Annahme- und Sicherheitsereignisse | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| INVUP-57 | Keine Secrets in Logs | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| INVUP-58 | Kein Docker-Socket | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| INVUP-59 | Keine unnötigen öffentlichen Backendports | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| INVUP-60 | Keine unnötigen privilegierten Container | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| INVUP-61 | Sicherheits- und Negativtests sind verpflichtend | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |

## 61 Schlusskriterien

| Nr. | Kriterium | Nachweis — bestanden |
|---|---|---|
| 1 | mTLS. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 2 | Gültige Clientzertifikate. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 3 | Sichere Zertifikatsidentitätsweitergabe. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 4 | API-Tokens. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 5 | Token-Serverbindung. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 6 | Scope-Prüfung. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 7 | Tokenablauf. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 8 | Tokenwiderruf. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 9 | Zertifikatswiderruf. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 10 | Technischer REST-Endpunkt. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 11 | JSON-Validierung. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 12 | Serveridentitätsprüfung. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 13 | Größenlimits. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 14 | Persistenz. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 15 | Idempotenz. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 16 | HTTP 202. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 17 | Statusabfrage. | tests/inventory_upload/integration/test_technical_security.py; echte Nginx-/CA-/CRL-/Tokenprüfungen |
| 18 | Session. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 19 | MFA. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 20 | CSRF. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 21 | Rollenberechtigung. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 22 | Objektbezogene Server-ACL. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 23 | Multipart-Datei. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 24 | Gemeinsamer Validator. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 25 | Gemeinsame Speicherung. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 26 | Statusabfrage. | tests/inventory_upload/integration/test_dashboard_security.py; Session/MFA/CSRF/RBAC/ACL |
| 27 | Registrierte Server-UUID. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 28 | Keine automatische Serverregistrierung. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 29 | Keine Gruppenänderung. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 30 | Keine Primärgruppenänderung. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 31 | Keine Sortieränderung. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 32 | Keine administrative Stammdatenänderung. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 33 | Unveränderlicher Annahmeinhalt. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 34 | Gesicherte Provenienz. | tests/inventory_upload/integration/test_acceptance.py und test_limits_integrity.py; native DB-Constraints und Rollen |
| 35 | Doppelte Einlieferungen. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 36 | Parallele Einlieferungen. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 37 | Idempotenzkonflikte. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 38 | PostgreSQL-Ausfälle. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 39 | API-Neustarts. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 40 | Persistente Annahmebestätigungen. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 41 | Keine vorgetäuschte Verarbeitung. | tests/inventory_upload/integration/test_concurrency_recovery.py; echte Transaktionen, Widerruf, Neustart, Restore |
| 42 | Keine Zertifikatsheader-Spoofing-Lücke. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 43 | Keine Token-Identitätsvermischung. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 44 | Keine BOLA-Lücke in den getesteten Statusendpunkten. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 45 | Kein CSRF. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 46 | Kein Mass Assignment. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 47 | Keine administrative Feldinjektion. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 48 | Ressourcenlimits. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 49 | Keine Secrets in Logs. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 50 | Keine unnötigen Containerprivilegien. | tests/inventory_upload/integration/test_operations_performance.py; Logs/Mounts/CLI; Deployment-/Regressionsnachweise unten |
| 51 | Ruff. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 52 | Mypy. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 53 | Unit-Tests. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 54 | PostgreSQL-Integrationstests. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 55 | Technische mTLS-Tests. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 56 | Dashboard-Integrationstests. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 57 | Sicherheitstests. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 58 | Konkurrenztests. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 59 | Ende-zu-Ende-Tests. | make check und vollständige getrennte Docker-Suiten; [Testmatrix](../testing/phase-11-test-matrix.md) |
| 60 | Dokumentation. | [Übergabe](phase-11-handover.md), neue API-Verträge, unverändertes Inventarformat 1.0 |
| 61 | Übergabe an Phase 12, 13 und 14. | [Übergabe](phase-11-handover.md), neue API-Verträge, unverändertes Inventarformat 1.0 |

## Reproduzierbare lokale Nachweise

`make check`; `CVE_DOCKER_SUDO=1 make inventory-upload-integration server-admin-integration
authorization-integration auth-integration automation-integration services-integration
db-test infra-test envoy-test mail-test`. Die einzelnen Suiten wurden vollständig separat
ausgeführt; die Befehlsfolge kann erneut verwendet werden. UUID-Projekte werden aufgeräumt.
Lokale erfolgreich abgeschlossene Protokolle liegen geschützt unter `.runtime/test-reports/`
mit Präfix `phase-11-`; Messwerte in `phase-11-performance.json`.
