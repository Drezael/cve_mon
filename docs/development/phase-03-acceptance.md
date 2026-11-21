# Phase-3-Gesamtabnahme

Stand: 06.11.2026. **Status: completed.** Alle 45 Aufgaben und sämtliche 36 Abnahmepunkte sind lokal geprüft.
149 Standardtests, 40 Infrastrukturtests und 189 Datenbanktests bestanden (378 Tests).

## Abnahmematrix

| ID | Prüfbereich | Erwartung | Nachweis | Status |
|---|---|---|---|---|
| A03.01 | PostgreSQL-Container | Startet erfolgreich | tests/database/test_roles.py; test_operations.py; test_database_tooling.py | passed |
| A03.02 | Persistenz | Daten überstehen Recreate | tests/database/test_roles.py; test_operations.py; test_database_tooling.py | passed |
| A03.03 | Netzwerk | Nur `cve_data` | tests/database/test_roles.py; test_operations.py; test_database_tooling.py | passed |
| A03.04 | Hostports | Kein öffentlicher Datenbankport | tests/database/test_roles.py; test_operations.py; test_database_tooling.py | passed |
| A03.05 | Secrets | Keine Klartextpasswörter im Repository | tests/database/test_roles.py; test_operations.py; test_database_tooling.py | passed |
| A03.06 | Erstinitialisierung | Funktioniert mit leerem Volume | tests/database/test_roles.py; test_operations.py; test_database_tooling.py | passed |
| A03.07 | Bestehendes Volume | Keine Neuinitialisierung | tests/database/test_roles.py; test_operations.py; test_database_tooling.py | passed |
| A03.08 | Datenbanken | `n8n` und `cve_monitoring` vorhanden | tests/database/test_roles.py; test_operations.py; test_database_tooling.py | passed |
| A03.09 | Rollen | Technische Rollen vorhanden | tests/database/test_roles.py; test_operations.py; test_database_tooling.py | passed |
| A03.10 | Isolation | Unberechtigte Zugriffe abgelehnt | database/migrations; tests/database/test_operations.py | passed |
| A03.11 | Migrationen | Erfolgreich und reproduzierbar | database/migrations; tests/database/test_operations.py | passed |
| A03.12 | Schemas | Alle acht vorhanden | database/migrations; tests/database/test_operations.py | passed |
| A03.13 | Server | Administrative Identität korrekt | tests/database/test_integrity.py | passed |
| A03.14 | Gruppen | Mehrfachzuordnungen möglich | tests/database/test_integrity.py | passed |
| A03.15 | Primärgruppe | Datenbankseitig konsistent | tests/database/test_integrity.py | passed |
| A03.16 | Sortierung | Persistente manuelle Reihenfolge | tests/database/test_integrity.py | passed |
| A03.17 | Inventarisolation | Keine Gruppen-Schreibrechte | tests/database/test_roles.py und test_integrity.py | passed |
| A03.18 | Inventare | Historisiert | tests/database/test_integrity.py | passed |
| A03.19 | Software | Vollständige Versionen gespeichert | tests/database/test_integrity.py | passed |
| A03.20 | CVEs | Originaldaten und Revisionen | tests/database/test_integrity.py | passed |
| A03.21 | Herstellerdaten | Quellen nachvollziehbar | tests/database/test_integrity.py | passed |
| A03.22 | Matching | Evidenz speicherbar | tests/database/test_integrity.py | passed |
| A03.23 | Findings | Statushistorie möglich | tests/database/test_integrity.py | passed |
| A03.24 | Benutzer | Kontenmodell vollständig | tests/database/test_integrity.py | passed |
| A03.25 | Berechtigungen | Rollen und Objektzugriffe | tests/database/test_integrity.py | passed |
| A03.26 | MFA | Geschützte Speicherung vorgesehen | tests/database/test_integrity.py | passed |
| A03.27 | Sessions | Persistente Sitzungsstruktur | tests/database/test_integrity.py | passed |
| A03.28 | Jobs | Persistente Jobzustände | tests/database/test_operations.py | passed |
| A03.29 | Outbox | Transaktionale Ereignisspeicherung | tests/database/test_operations.py | passed |
| A03.30 | Audit | Nachvollziehbare Ereignisse | tests/database/test_operations.py; docs/deployment/postgresql.md; phase-03-handover.md | passed |
| A03.31 | Dashboard | Präferenzen und Sortiermodus getrennt | tests/database/test_operations.py; docs/deployment/postgresql.md; phase-03-handover.md | passed |
| A03.32 | Datenbanktests | Erfolgreich | tests/database/test_operations.py; docs/deployment/postgresql.md; phase-03-handover.md | passed |
| A03.33 | Backup | Erfolgreich | tests/database/test_operations.py; docs/deployment/postgresql.md; phase-03-handover.md | passed |
| A03.34 | Restore | Erfolgreich | tests/database/test_operations.py; docs/deployment/postgresql.md; phase-03-handover.md | passed |
| A03.35 | Dokumentation | Vollständig | tests/database/test_operations.py; docs/deployment/postgresql.md; phase-03-handover.md | passed |
| A03.36 | Übergabe | Vorbereitet | tests/database/test_operations.py; docs/deployment/postgresql.md; phase-03-handover.md | passed |

## Pflichtprüfungen und konkrete Grenzen

Die vollständige 40-Punkte-Liste T03.09.05 wird durch die vorstehenden Nachweise und folgende
Gruppen geprüft: Instanz/Netz/Port/Secret/Volume; Datenbanken/Logins/ACLs/Schemas/Migrationen;
Server/Gruppen/Primärgruppe/Positionen; Inventarhistorie/Qualität; CVE/Matching/Findings;
Security/RBAC/MFA/Sessions; Jobs/Outbox/Audit/Präferenzen; Backup/Restore/Dokumentation/Übergabe.
Kein verpflichtender Datenbanktest wird mangels Daemon still übersprungen.

DB-Tests verwenden eigene Projekte und echte TLS-/SCRAM-Logins. Backups/Restores enthalten
synthetische Daten; externe MFA-/n8n-Schlüssel bleiben bewusst außerhalb der Datenbanksicherung.
Der Restore vergleicht vollständige Tabellenfingerprints, Rollen, Eigentümer, ACLs, Constraints,
Indizes, Policies, Funktionen, Defaultprivilegien und Alembic-Head bei gestoppter Quelle.
Fehlerhafte und tatsächlich abgebrochene Migrationen hinterlassen keinen neuen Versionsstand.

Keine Produktivfreigabe: Host-Firewall und produktive PKI sind weiterhin Betreiberaufgaben
wie in Phase 2. Phase 3 benötigt dafür keine Veränderung fremder Hostregeln.
Fachliche letzte-Administrator-/MFA-/CSRF-/Upload-/Workerregeln folgen den vorgesehenen Phasen;
die DB-Grundlage, Grenzen und transaktionalen Pflichten sind jetzt implementiert/dokumentiert.
Git-Remote/Commit/Push und ein gehosteter CI-Lauf wurden nicht beauftragt.

[Aufgabenstatus](phase-03-status.md), [Detailmatrix](../testing/phase-03-test-matrix.md),
[bewusster Vertragsabgleich](../architecture/decisions/ADR-0021-postgresql-phase03.md).


## Ausgeführte Abschlussprüfungen

| Befehl / Prüfung | Ergebnis |
|---|---|
| make setup | Hashgesperrte Installation/Wiederholung und pip check erfolgreich |
| make check | Ruff-Lint, Format, Mypy strict (38 Dateien), 149 Standardtests, YAML/JSON/OpenAPI/Inventarbeispiele und lokale Dokumentverweise, Compose-Basis/Development und Secret-Scan erfolgreich |
| CVE_DOCKER_SUDO=1 make infra-test | 40 echte Docker-/Nginx-/TLS-/mTLS-/Netzwerktests bestanden |
| CVE_DOCKER_SUDO=1 make db-test | 189 echte PostgreSQL-Tests bestanden, keine Skips; Laufzeit ca. 101 Sekunden |
| Zusätzlicher Audit-Negativlauf | 3 aktuelle Parametervarianten nach Entfernen statischer Secret-Testwerte bestanden |
| CVE_DOCKER_SUDO=1 make db-check | Head 00012_original_identity, acht Fachschemas, 16 erfolgreiche Anwendungslogins |
| Normaler Entwicklungscluster | Keine geseedeten Benutzer, keine n8n-internen Tabellen; Schema vollständig migriert |
| Quellkonzepte/Baseline | SHA-256 aller vier Originalphasen und .secrets.baseline unverändert |
| Ressourcen | Eigene Test-/Restoreprojekte entfernt; Entwicklungs-PostgreSQL gestoppt, Volume/Secrets erhalten; fremde Nextcloud-Instanz unverändert |

PostgreSQL 18.6, Python 3.12.3, Alembic 1.20.1, Psycopg 3.3.8, SQLAlchemy 2.1.8.
Alle laufenden Werkzeuge stammen aus der Projektvenv. Zwölf versionierte DDL-Schritte;
`0001_foundation` separat auf leerem Volume geprüft, dann vollständiger Head und Wiederholung.
Die CI-Befehle sind ergänzt, ein gehosteter GitHub-Lauf mangels Veröffentlichung bleibt aus.
Der Secret-Scan behält die leere Baseline; eine lokale Inline-Ausnahme kennzeichnet ausschließlich
den öffentlichen Algorithmusnamen in password_encryption, kein Credential.

## Vollständige 40-Punkte-Prüfung T03.09.05

| Nr. | Vorgabe | Ergebnis / Nachweisgruppe |
|---|---|---|
| 1 | PostgreSQL startet. | passed — Rollen-/Container-/Persistenztests |
| 2 | PostgreSQL-Konfiguration gültig. | passed — Rollen-/Container-/Persistenztests |
| 3 | Datenvolume persistent. | passed — Rollen-/Container-/Persistenztests |
| 4 | Keine öffentlichen Datenbankports. | passed — Rollen-/Container-/Persistenztests |
| 5 | Datenbankzugang geschützt. | passed — Rollen-/Container-/Persistenztests |
| 6 | Keine Klartext-Secrets im Repository. | passed — Rollen-/Container-/Persistenztests |
| 7 | Datenbanken `n8n` und `cve_monitoring` vorhanden. | passed — Rollen-/Container-/Persistenztests |
| 8 | Technische Rollen erstellt. | passed — Rollen-/Container-/Persistenztests |
| 9 | Rollenrechte korrekt. | passed — Rollen-/Container-/Persistenztests |
| 10 | Acht Fachschemas vorhanden. | passed — Schema-/Migrations- und Wiederholungstests |
| 11 | Migrationen erfolgreich. | passed — Schema-/Migrations- und Wiederholungstests |
| 12 | Migrationen reproduzierbar. | passed — Schema-/Migrations- und Wiederholungstests |
| 13 | Serverstammdaten korrekt. | passed — Integritäts-/Inventar-/Konkurrenztests |
| 14 | Gruppenmodell korrekt. | passed — Integritäts-/Inventar-/Konkurrenztests |
| 15 | Mehrfachzuordnung korrekt. | passed — Integritäts-/Inventar-/Konkurrenztests |
| 16 | Primärgruppen-Konsistenz sichergestellt. | passed — Integritäts-/Inventar-/Konkurrenztests |
| 17 | Manuelle Sortierung persistent. | passed — Integritäts-/Inventar-/Konkurrenztests |
| 18 | Inventarisolation nachgewiesen. | passed — Integritäts-/Inventar-/Konkurrenztests |
| 19 | Inventar-Snapshots historisierbar. | passed — Integritäts-/Inventar-/Konkurrenztests |
| 20 | Softwarepakete korrekt gespeichert. | passed — Integritäts-/Inventar-/Konkurrenztests |
| 21 | CVE-Datenmodell vorhanden. | passed — CVE-/Matching-/Finding-/Securitytests |
| 22 | CVE-Revisionen möglich. | passed — CVE-/Matching-/Finding-/Securitytests |
| 23 | Matching-Modell vorhanden. | passed — CVE-/Matching-/Finding-/Securitytests |
| 24 | Finding-Modell vorhanden. | passed — CVE-/Matching-/Finding-/Securitytests |
| 25 | Benutzerkontenmodell vorhanden. | passed — CVE-/Matching-/Finding-/Securitytests |
| 26 | Rollen- und Berechtigungstabellen vorhanden. | passed — CVE-/Matching-/Finding-/Securitytests |
| 27 | MFA-Datenmodell vorhanden. | passed — CVE-/Matching-/Finding-/Securitytests |
| 28 | Session-Modell vorhanden. | passed — CVE-/Matching-/Finding-/Securitytests |
| 29 | Jobtabellen vorhanden. | passed — Job-/Outbox-/Audit-/Präferenztests |
| 30 | Outbox vorhanden. | passed — Job-/Outbox-/Audit-/Präferenztests |
| 31 | Auditdatenmodell vorhanden. | passed — Job-/Outbox-/Audit-/Präferenztests |
| 32 | Dashboard-Präferenzen vorhanden. | passed — Job-/Outbox-/Audit-/Präferenztests |
| 33 | Keine automatische Gruppierung. | passed — Isolation und vollständige Testsuite |
| 34 | n8n-Datenbank isoliert. | passed — Isolation und vollständige Testsuite |
| 35 | Keine übermäßigen Datenbankrechte. | passed — Isolation und vollständige Testsuite |
| 36 | Datenbanktests erfolgreich. | passed — Isolation und vollständige Testsuite |
| 37 | Backup erfolgreich. | passed — Echtes Backup/Restore bei gestoppter Quelle |
| 38 | Restore erfolgreich. | passed — Echtes Backup/Restore bei gestoppter Quelle |
| 39 | Dokumentation vollständig. | passed — Dokumentverweise, Betriebsdokumente und Übergabe |
| 40 | Übergabe an die nächste Phase vorbereitet. | passed — Dokumentverweise, Betriebsdokumente und Übergabe |
