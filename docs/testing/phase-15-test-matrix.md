# Phase 15 – Testmatrix

Tests verwenden eigene PostgreSQL-Projekte, echte Runtime-Rollen und kontrollierte Quellfixtures.
Docker-E2E verwendet das gebaute Image, echte HTTPS-Sockets, Envoy CONNECT und Namespacefilter.
Externe Vollbestände werden nicht automatisch heruntergeladen.

| Kriterium | Forderung | Nachweis |
|---|---|---|
| A15-001 | Tatsächlicher Repository-Stand berücksichtigt. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-002 | Vorhandene Architektur verwendet. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-003 | Dienst `cve-importer` implementiert. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-004 | Python 3.12 verwendet. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-005 | Gemeinsame Servicebasis verwendet. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-006 | PostgreSQL als einzige Datenbank. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-007 | Datenbankschema `cve` verwendet. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-008 | Vorhandene Migrationen berücksichtigt. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-009 | Neue Migrationen versioniert. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-010 | Kein Redis. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-011 | Kein MongoDB. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-012 | Kein zusätzlicher Broker. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-013 | Keine zusätzliche Workflow-Engine. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-014 | Vorhandene PostgreSQL-Worker verwendet. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-015 | Vorhandene Transactional Outbox verwendet. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-016 | Quellenregister vorhanden. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-017 | Alle fünf Quellen registriert. | Bestandsanalyse/ADR-0033, Migration, Compose und Qualitätsprüfung |
| A15-018 | Unabhängige Importläufe je Quelle. | test_pipeline: Initial/Repeat/Partial/Recovery; source_streams |
| A15-019 | Unabhängige Cursor je Quelle. | test_pipeline: Initial/Repeat/Partial/Recovery; source_streams |
| A15-020 | Initialimporte möglich. | test_pipeline: Initial/Repeat/Partial/Recovery; source_streams |
| A15-021 | Inkrementelle Importe möglich. | test_pipeline: Initial/Repeat/Partial/Recovery; source_streams |
| A15-022 | Reconciliation vorbereitet. | test_pipeline: Initial/Repeat/Partial/Recovery; source_streams |
| A15-023 | Keine vorzeitigen Cursorupdates. | test_pipeline: Initial/Repeat/Partial/Recovery; source_streams |
| A15-024 | CVEProject-Quelle funktioniert. | test_validation + test_pipeline + test_container: CVEProject |
| A15-025 | Offizielle Basispakete unterstützt. | test_validation + test_pipeline + test_container: CVEProject |
| A15-026 | Delta-Synchronisierung funktioniert. | test_validation + test_pipeline + test_container: CVEProject |
| A15-027 | Fehlende Delta-Pakete werden erkannt. | test_validation + test_pipeline + test_container: CVEProject |
| A15-028 | CVE-Record-Version 5.0 unterstützt. | test_validation + test_pipeline + test_container: CVEProject |
| A15-029 | CVE-Record-Version 5.1 unterstützt. | test_validation + test_pipeline + test_container: CVEProject |
| A15-030 | CVE-Record-Version 5.1.1 unterstützt. | test_validation + test_pipeline + test_container: CVEProject |
| A15-031 | CVE-Record-Version 5.2.0 unterstützt. | test_validation + test_pipeline + test_container: CVEProject |
| A15-032 | CNA-Container erhalten. | test_validation + test_pipeline + test_container: CVEProject |
| A15-033 | CVE-Program-Container erhalten. | test_validation + test_pipeline + test_container: CVEProject |
| A15-034 | ADP-Container erhalten. | test_validation + test_pipeline + test_container: CVEProject |
| A15-035 | CVE-ID validiert. | test_validation + test_pipeline + test_container: CVEProject |
| A15-036 | PUBLISHED-Records korrekt. | test_validation + test_pipeline + test_container: CVEProject |
| A15-037 | REJECTED-Records historisiert. | test_validation + test_pipeline + test_container: CVEProject |
| A15-038 | NVD API 2.0 funktioniert. | test_pipeline: Pagination/Einzelrecordfehler; test_transport: Rate/Key |
| A15-039 | NVD-Pagination vollständig. | test_pipeline: Pagination/Einzelrecordfehler; test_transport: Rate/Key |
| A15-040 | NVD-Änderungsfenster korrekt. | test_pipeline: Pagination/Einzelrecordfehler; test_transport: Rate/Key |
| A15-041 | NVD-Rate-Limits eingehalten. | test_pipeline: Pagination/Einzelrecordfehler; test_transport: Rate/Key |
| A15-042 | NVD-API-Key geschützt. | test_pipeline: Pagination/Einzelrecordfehler; test_transport: Rate/Key |
| A15-043 | Große NVD-Änderungsmengen unterstützt. | test_pipeline: Pagination/Einzelrecordfehler; test_transport: Rate/Key |
| A15-044 | CISA-KEV-Import funktioniert. | test_pipeline: KEV-Historie/Regression/Entfernung; Container-E2E |
| A15-045 | KEV-Katalogversion gespeichert. | test_pipeline: KEV-Historie/Regression/Entfernung; Container-E2E |
| A15-046 | KEV-Eintragsanzahl geprüft. | test_pipeline: KEV-Historie/Regression/Entfernung; Container-E2E |
| A15-047 | KEV-Historie erhalten. | test_pipeline: KEV-Historie/Regression/Entfernung; Container-E2E |
| A15-048 | Keine Löschung durch unvollständigen KEV-Download. | test_pipeline: KEV-Historie/Regression/Entfernung; Container-E2E |
| A15-049 | Ubuntu-Security-Import funktioniert. | Quellenvertrag Ubuntu; test_validation/test_pipeline/Container-E2E |
| A15-050 | Ubuntu-CVE-Daten erhalten. | Quellenvertrag Ubuntu; test_validation/test_pipeline/Container-E2E |
| A15-051 | Ubuntu Security Notices berücksichtigt. | Quellenvertrag Ubuntu; test_validation/test_pipeline/Container-E2E |
| A15-052 | Ubuntu-Release-Zuordnung erhalten. | Quellenvertrag Ubuntu; test_validation/test_pipeline/Container-E2E |
| A15-053 | Ubuntu-Paketversionen vollständig erhalten. | Quellenvertrag Ubuntu; test_validation/test_pipeline/Container-E2E |
| A15-054 | OSV-Import funktioniert. | OSV-Dump/Index/Alias/Withdrawn/Stale in test_pipeline |
| A15-055 | OSV-Full-Dump unterstützt. | OSV-Dump/Index/Alias/Withdrawn/Stale in test_pipeline |
| A15-056 | OSV-Änderungsindex unterstützt. | OSV-Dump/Index/Alias/Withdrawn/Stale in test_pipeline |
| A15-057 | OSV-Aliase erhalten. | OSV-Dump/Index/Alias/Withdrawn/Stale in test_pipeline |
| A15-058 | OSV-Withdrawn-Status berücksichtigt. | OSV-Dump/Index/Alias/Withdrawn/Stale in test_pipeline |
| A15-059 | Keine automatische CVE-Gleichsetzung. | OSV-Dump/Index/Alias/Withdrawn/Stale in test_pipeline |
| A15-060 | Keine Überschreibung zwischen Quellen. | OSV-Dump/Index/Alias/Withdrawn/Stale in test_pipeline |
| A15-061 | JSONB-Rohdaten gespeichert. | Migration/FKs; native Immutability/Hash/Repeat/Restore in test_pipeline |
| A15-062 | SHA-256-Hash gespeichert. | Migration/FKs; native Immutability/Hash/Repeat/Restore in test_pipeline |
| A15-063 | Quellenprovenienz gespeichert. | Migration/FKs; native Immutability/Hash/Repeat/Restore in test_pipeline |
| A15-064 | Externe Record-ID gespeichert. | Migration/FKs; native Immutability/Hash/Repeat/Restore in test_pipeline |
| A15-065 | Quellenzeitstempel erhalten. | Migration/FKs; native Immutability/Hash/Repeat/Restore in test_pipeline |
| A15-066 | Importzeitstempel erhalten. | Migration/FKs; native Immutability/Hash/Repeat/Restore in test_pipeline |
| A15-067 | Unveränderliche Revisionen. | Migration/FKs; native Immutability/Hash/Repeat/Restore in test_pipeline |
| A15-068 | Neue Revision bei geänderten Datensätzen. | Migration/FKs; native Immutability/Hash/Repeat/Restore in test_pipeline |
| A15-069 | Keine neue Revision bei identischen Datensätzen. | Migration/FKs; native Immutability/Hash/Repeat/Restore in test_pipeline |
| A15-070 | Alte Revisionen bleiben erhalten. | Migration/FKs; native Immutability/Hash/Repeat/Restore in test_pipeline |
| A15-071 | Keine unkontrollierte Datenlöschung. | Migration/FKs; native Immutability/Hash/Repeat/Restore in test_pipeline |
| A15-072 | Sichere Archivverarbeitung. | test_validation/test_transport: Parser, Archive, Versionen, Limits, Partial |
| A15-073 | Größenlimits funktionieren. | test_validation/test_transport: Parser, Archive, Versionen, Limits, Partial |
| A15-074 | Dekompressionslimits funktionieren. | test_validation/test_transport: Parser, Archive, Versionen, Limits, Partial |
| A15-075 | Schutz vor Zip-Bombs. | test_validation/test_transport: Parser, Archive, Versionen, Limits, Partial |
| A15-076 | Schutz vor Path Traversal. | test_validation/test_transport: Parser, Archive, Versionen, Limits, Partial |
| A15-077 | Keine Ausführung von Quellinhalten. | test_validation/test_transport: Parser, Archive, Versionen, Limits, Partial |
| A15-078 | JSON-Schema-Validierung funktioniert. | test_validation/test_transport: Parser, Archive, Versionen, Limits, Partial |
| A15-079 | Unbekannte Schema-Versionen werden abgelehnt. | test_validation/test_transport: Parser, Archive, Versionen, Limits, Partial |
| A15-080 | Fehlerhafte Records werden nachvollziehbar behandelt. | test_validation/test_transport: Parser, Archive, Versionen, Limits, Partial |
| A15-081 | Kein falscher vollständiger Importstatus. | test_validation/test_transport: Parser, Archive, Versionen, Limits, Partial |
| A15-082 | Envoy-Egress wird verwendet. | test_transport/test_container und 77 vorhandene Envoy-Tests |
| A15-083 | Direkter Egress ist blockiert. | test_transport/test_container und 77 vorhandene Envoy-Tests |
| A15-084 | Nicht freigegebene Hosts werden blockiert. | test_transport/test_container und 77 vorhandene Envoy-Tests |
| A15-085 | Redirect-Allowlist funktioniert. | test_transport/test_container und 77 vorhandene Envoy-Tests |
| A15-086 | TLS-Zertifikatsprüfung aktiv. | test_transport/test_container und 77 vorhandene Envoy-Tests |
| A15-087 | Kein TLS-Downgrade. | test_transport/test_container und 77 vorhandene Envoy-Tests |
| A15-088 | SSRF-Schutz berücksichtigt. | test_transport/test_container und 77 vorhandene Envoy-Tests |
| A15-089 | Proxy-Ausfall führt nicht zu direktem Fallback. | test_transport/test_container und 77 vorhandene Envoy-Tests |
| A15-090 | Keine Secrets in Logs. | test_transport/test_container und 77 vorhandene Envoy-Tests |
| A15-091 | Keine Secrets in Rohdatensätzen. | test_transport/test_container und 77 vorhandene Envoy-Tests |
| A15-092 | Keine unberechtigten Datenbankrechte. | test_database native Denials; test_container Runtime-Härtung |
| A15-093 | Keine Schreibrechte auf Servergruppen. | test_database native Denials; test_container Runtime-Härtung |
| A15-094 | Keine Schreibrechte auf Primärgruppen. | test_database native Denials; test_container Runtime-Härtung |
| A15-095 | Keine Schreibrechte auf Sortierungen. | test_database native Denials; test_container Runtime-Härtung |
| A15-096 | Keine Schreibrechte auf Benutzer-ACLs. | test_database native Denials; test_container Runtime-Härtung |
| A15-097 | Keine Schreibrechte auf Inventarsnapshots. | test_database native Denials; test_container Runtime-Härtung |
| A15-098 | Keine Schreibrechte auf Findings. | test_database native Denials; test_container Runtime-Härtung |
| A15-099 | Kein Docker-Socket. | test_database native Denials; test_container Runtime-Härtung |
| A15-100 | Keine unnötigen öffentlichen Ports. | test_database native Denials; test_container Runtime-Härtung |
| A15-101 | Keine unnötigen Containerprivilegien. | test_database native Denials; test_container Runtime-Härtung |
| A15-102 | Kontrollierte Workerparallelität. | test_pipeline Recovery/Fence/Concurrency; test_container Ausfälle/SIGKILL |
| A15-103 | Kontrollierte Retryanzahl. | test_pipeline Recovery/Fence/Concurrency; test_container Ausfälle/SIGKILL |
| A15-104 | Worker-Leases funktionieren. | test_pipeline Recovery/Fence/Concurrency; test_container Ausfälle/SIGKILL |
| A15-105 | Workerabstürze sind wiederaufnehmbar. | test_pipeline Recovery/Fence/Concurrency; test_container Ausfälle/SIGKILL |
| A15-106 | PostgreSQL-Ausfälle werden behandelt. | test_pipeline Recovery/Fence/Concurrency; test_container Ausfälle/SIGKILL |
| A15-107 | Keine doppelten Revisionen nach Retry. | test_pipeline Recovery/Fence/Concurrency; test_container Ausfälle/SIGKILL |
| A15-108 | Keine Cursorverluste nach Recovery. | test_pipeline Recovery/Fence/Concurrency; test_container Ausfälle/SIGKILL |
| A15-109 | Outbox-Ereignisse transaktional. | test_pipeline Recovery/Fence/Concurrency; test_container Ausfälle/SIGKILL |
| A15-110 | Keine vollständigen Payloads in Outbox-Ereignissen. | test_pipeline Recovery/Fence/Concurrency; test_container Ausfälle/SIGKILL |
| A15-111 | Keine CVE-Anreicherung vorzeitig implementiert. | Native Rechte + leere Fremd-Fachtabellen + Architekturgrenze |
| A15-112 | Keine CVE-Matchingberechnung. | Native Rechte + leere Fremd-Fachtabellen + Architekturgrenze |
| A15-113 | Keine Finding-Erzeugung. | Native Rechte + leere Fremd-Fachtabellen + Architekturgrenze |
| A15-114 | Kein direkter Zugriff auf verwaltete Server. | Native Rechte + leere Fremd-Fachtabellen + Architekturgrenze |
| A15-115 | Unit-Tests erfolgreich. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-116 | PostgreSQL-Integrationstests erfolgreich. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-117 | Quellenadaptertests erfolgreich. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-118 | Envoy-Integrationstests erfolgreich. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-119 | Sicherheitstests erfolgreich. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-120 | Archiv- und Parsertests erfolgreich. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-121 | Cursor- und Reconciliation-Tests erfolgreich. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-122 | Retry- und Recovery-Tests erfolgreich. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-123 | Konkurrenztests erfolgreich. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-124 | Performance-Baseline dokumentiert. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-125 | Ende-zu-Ende-Test erfolgreich. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-126 | Dokumentation vollständig. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-127 | Übergabe an Phase 16 vorbereitet. | Ausgeführte Schlussprüfungen im Abnahmebericht |
| A15-128 | Keine unzulässigen Architekturänderungen. | Ausgeführte Schlussprüfungen im Abnahmebericht |

## Reproduzierbare Befehle

make check; make cve-importer-check; make cve-importer-integration; make db-test;
make automation-integration; make envoy-test; make infra-test; make services-integration.
Alle Dockerziele bei Bedarf mit CVE_DOCKER_SUDO=1.

Private Laufprotokolle und JUnitberichte: .runtime/test-reports/phase-15-*.

## Sicherheitsinvarianten

| ID | Invariante | Nachweisgruppe |
|---|---|---|
| IMP-01 | CVEProject/cvelistV5 ist die primäre offizielle CVE-Quelle | Quellenverträge, native Pipeline und Revisionstests |
| IMP-02 | NVD bleibt eine eigenständige ergänzende Quelle | Quellenverträge, native Pipeline und Revisionstests |
| IMP-03 | CISA KEV bleibt eine eigenständige Quelle | Quellenverträge, native Pipeline und Revisionstests |
| IMP-04 | Ubuntu Security bleibt eine eigenständige Quelle | Quellenverträge, native Pipeline und Revisionstests |
| IMP-05 | OSV bleibt eine eigenständige Quelle | Quellenverträge, native Pipeline und Revisionstests |
| IMP-06 | Kein Quellrecord überschreibt einen anderen Quellrecord | Quellenverträge, native Pipeline und Revisionstests |
| IMP-07 | CVE-ID und externe Advisory-ID werden unterschieden | Quellenverträge, native Pipeline und Revisionstests |
| IMP-08 | Quellidentität bleibt erhalten | Quellenverträge, native Pipeline und Revisionstests |
| IMP-09 | JSONB-Rohinhalt bleibt semantisch unverändert | Quellenverträge, native Pipeline und Revisionstests |
| IMP-10 | Ursprünglicher Byte-Hash wird separat gespeichert | Quellenverträge, native Pipeline und Revisionstests |
| IMP-11 | Historische Revisionen bleiben unverändert | Quellenverträge, native Pipeline und Revisionstests |
| IMP-12 | Geänderte Quelldaten erzeugen eine neue Revision | Quellenverträge, native Pipeline und Revisionstests |
| IMP-13 | Identische Quelldaten erzeugen keine unnötige neue Revision | Quellenverträge, native Pipeline und Revisionstests |
| IMP-14 | Keine automatische Quellenfusion | Quellenverträge, native Pipeline und Revisionstests |
| IMP-15 | Keine fachliche Quellenpriorisierung in Phase 15 | Quellenverträge, native Pipeline und Revisionstests |
| IMP-16 | Keine CVE-Matchingentscheidung | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-17 | Keine Finding-Erzeugung | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-18 | Keine automatische Serverregistrierung | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-19 | Keine Änderung administrativer Serverdaten | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-20 | Keine Gruppenänderung | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-21 | Keine Primärgruppenänderung | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-22 | Keine Sortieränderung | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-23 | Keine ACL-Änderung | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-24 | Kein Zugriff auf verwaltete Server | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-25 | Keine SSH- oder Ansible-Verbindung | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-26 | Keine Docker-Engine-Verbindung | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-27 | Kein Docker-Socket | Native Rechte, Container-Netzgrenze, unveränderte Verwaltung |
| IMP-28 | Alle externen HTTP(S)-Verbindungen ausschließlich über Envoy | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-29 | Kein direkter Internet-Fallback | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-30 | TLS-Zertifikate werden validiert | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-31 | Keine ungeprüften Downloadhosts | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-32 | Keine offenen Redirects | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-33 | SSRF-Schutz bleibt aktiv | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-34 | Downloadgrößen sind begrenzt | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-35 | Entpackte Archivgrößen sind begrenzt | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-36 | Archivpfade werden kontrolliert | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-37 | Keine Ausführung von Quellinhalten | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-38 | Alle Quelldokumente werden validiert | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-39 | Unbekannte Formatversionen werden kontrolliert behandelt | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-40 | REJECTED-Records bleiben historisch erhalten | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-41 | Withdrawn-Records bleiben historisch erhalten | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-42 | Keine Löschung durch unvollständige Downloads | Transport-/Envoy-/TLS-/Archiv-/Schema-Negativtests |
| IMP-43 | Cursor werden nur nach vollständiger sicherer Verarbeitung weitergestellt | Checkpoint-/Fence-/Retry-/Concurrency-/Recoveryfälle |
| IMP-44 | Quellen besitzen unabhängige Cursor | Checkpoint-/Fence-/Retry-/Concurrency-/Recoveryfälle |
| IMP-45 | Synchronisationslücken werden erkannt | Checkpoint-/Fence-/Retry-/Concurrency-/Recoveryfälle |
| IMP-46 | Überlappende Änderungsfenster werden unterstützt | Checkpoint-/Fence-/Retry-/Concurrency-/Recoveryfälle |
| IMP-47 | Wiederholte Importe sind idempotent | Checkpoint-/Fence-/Retry-/Concurrency-/Recoveryfälle |
| IMP-48 | Worker-Leases werden verwendet | Checkpoint-/Fence-/Retry-/Concurrency-/Recoveryfälle |
| IMP-49 | Retries sind begrenzt | Checkpoint-/Fence-/Retry-/Concurrency-/Recoveryfälle |
| IMP-50 | Fehlerhafte Importe werden nicht als vollständig gemeldet | Checkpoint-/Fence-/Retry-/Concurrency-/Recoveryfälle |
| IMP-51 | Kein Redis | Architektur/Compose, Outbox, Runtime-/Secret-/Rollenprüfung |
| IMP-52 | Keine zusätzliche Datenbank | Architektur/Compose, Outbox, Runtime-/Secret-/Rollenprüfung |
| IMP-53 | Kein zusätzlicher Message Broker | Architektur/Compose, Outbox, Runtime-/Secret-/Rollenprüfung |
| IMP-54 | PostgreSQL bleibt das einzige Datenbanksystem | Architektur/Compose, Outbox, Runtime-/Secret-/Rollenprüfung |
| IMP-55 | Transactional Outbox wird verwendet | Architektur/Compose, Outbox, Runtime-/Secret-/Rollenprüfung |
| IMP-56 | Keine vollständigen Rohpayloads in Outbox-Ereignissen | Architektur/Compose, Outbox, Runtime-/Secret-/Rollenprüfung |
| IMP-57 | Keine Secrets in Logs | Architektur/Compose, Outbox, Runtime-/Secret-/Rollenprüfung |
| IMP-58 | Keine unnötigen öffentlichen Ports | Architektur/Compose, Outbox, Runtime-/Secret-/Rollenprüfung |
| IMP-59 | Keine unnötigen Containerprivilegien | Architektur/Compose, Outbox, Runtime-/Secret-/Rollenprüfung |
| IMP-60 | Technische Datenbankrechte sind minimal | Architektur/Compose, Outbox, Runtime-/Secret-/Rollenprüfung |
| IMP-61 | Keine PostgreSQL-Superuser-Rechte im Importer | Architektur/Compose, Outbox, Runtime-/Secret-/Rollenprüfung |
| IMP-62 | Große Importe sind ressourcenbegrenzt | Performance, Recovery, OSV-Konfiguration und Abschlussbericht |
| IMP-63 | Initialimporte sind wiederaufnehmbar | Performance, Recovery, OSV-Konfiguration und Abschlussbericht |
| IMP-64 | Inkrementelle Importe sind wiederaufnehmbar | Performance, Recovery, OSV-Konfiguration und Abschlussbericht |
| IMP-65 | Kein automatischer Download sämtlicher OSV-Ökosysteme ohne Freigabe | Performance, Recovery, OSV-Konfiguration und Abschlussbericht |
| IMP-66 | Keine externe n8n-Abhängigkeit für den Import | Performance, Recovery, OSV-Konfiguration und Abschlussbericht |
| IMP-67 | Keine Git-Commits ohne Auftrag | Performance, Recovery, OSV-Konfiguration und Abschlussbericht |
| IMP-68 | Kein Git-Push ohne Auftrag | Performance, Recovery, OSV-Konfiguration und Abschlussbericht |
| IMP-69 | Quellen- und Sicherheitsintegrationstests sind verpflichtend | Performance, Recovery, OSV-Konfiguration und Abschlussbericht |
| IMP-70 | Fehlende Voraussetzungen werden offen dokumentiert | Performance, Recovery, OSV-Konfiguration und Abschlussbericht |
