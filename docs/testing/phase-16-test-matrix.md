# Phase 16 – Testmatrix

Eigene PostgreSQL-/Dockerprojekte, echte Rollen, Leases/Fencing und HTTPS-Sockets
mit Envoy. Keine Live-Serverinventare oder administrativen Daten werden verändert.

| Kriterium | Forderung | Nachweisgruppe |
|---|---|---|
| A16-001 | Vorhandene Architektur berücksichtigt. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-002 | Bestehender Dienst `cve-enricher` verwendet. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-003 | Python 3.12 verwendet. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-004 | PostgreSQL als einzige Datenbank. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-005 | Schema `cve` verwendet. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-006 | Vorhandene Workerinfrastruktur verwendet. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-007 | Transactional Outbox verwendet. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-008 | Kein Redis. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-009 | Kein MongoDB. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-010 | Kein zusätzlicher Broker. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-011 | Keine neue Workflow-Engine. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-012 | Kein zweiter Enrichment-Microservice. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-013 | Keine zusätzlichen öffentlichen Ports. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-014 | Keine unnötigen Containerprivilegien. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-015 | Kein Docker-Socket. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-016 | Keine SSH-Verbindungen. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-017 | Keine Ansible-Aufrufe. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-018 | Keine automatische Serverinventarisierung. | Bestandsanalyse, ADR-0034, Compose und gemeinsame Worker-/Outboxbasis |
| A16-019 | CVEProject-Rohdaten verarbeitet. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-020 | NVD-Rohdaten verarbeitet. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-021 | CISA-KEV-Rohdaten verarbeitet. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-022 | Ubuntu-Sicherheitsdaten verarbeitet. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-023 | OSV-Daten verarbeitet. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-024 | Keine Rohdatenüberschreibung. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-025 | CVE-Identitäten korrekt. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-026 | Advisory-Identitäten korrekt. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-027 | Aliasbeziehungen korrekt. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-028 | Mehrfachaliase unterstützt. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-029 | Keine unzulässige CVE-Verschmelzung. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-030 | Keine erfundenen CVE-IDs. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-031 | Quellenpriorisierung feldbezogen. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-032 | Quellenpriorisierung dokumentiert. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-033 | Provenienz je relevanter Aussage. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-034 | CVE-Lebenszyklus korrekt. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-035 | PUBLISHED korrekt. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-036 | REJECTED korrekt. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-037 | Historische Zustände bleiben erhalten. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-038 | Beschreibungen korrekt. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-039 | CWE-Referenzen korrekt. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-040 | Sicherheitsreferenzen korrekt. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-041 | Konflikte werden erkannt. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-042 | Konflikte bleiben nachvollziehbar. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-043 | Keine unkontrollierte Quellenmehrheit. | test_native/test_container: fünf Quellen, Provenienz und getrennte Identitäten |
| A16-044 | CVSS v2.0 unterstützt. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-045 | CVSS v3.0 unterstützt. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-046 | CVSS v3.1 unterstützt. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-047 | CVSS v4.0 unterstützt. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-048 | CVSS-Vektoren validiert. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-049 | CVSS-Scores validiert. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-050 | CVSS-Bewertungsherkunft gespeichert. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-051 | Mehrere Bewertungen bleiben erhalten. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-052 | Bevorzugte Bewertung nachvollziehbar. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-053 | Keine ungeprüfte Scoreberechnung. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-054 | Keine frei erfundene Risikozahl. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-055 | Keine serverbezogene Environmental-Bewertung. | test_normalize: veröffentlichte CVSS-Beispiele, ungültige Vektoren/Scores, Präferenz |
| A16-056 | KEV-Zugehörigkeit korrekt. | test_native: vollständige KEV-Mitgliedschaft und dynamische Stale-Kennzeichnung |
| A16-057 | KEV-Katalogreferenz vorhanden. | test_native: vollständige KEV-Mitgliedschaft und dynamische Stale-Kennzeichnung |
| A16-058 | KEV-Datenalter berücksichtigt. | test_native: vollständige KEV-Mitgliedschaft und dynamische Stale-Kennzeichnung |
| A16-059 | Kein falscher KEV-Negativstatus. | test_native: vollständige KEV-Mitgliedschaft und dynamische Stale-Kennzeichnung |
| A16-060 | Ransomware-Kennzeichnung korrekt. | test_native: vollständige KEV-Mitgliedschaft und dynamische Stale-Kennzeichnung |
| A16-061 | CISA-Due-Date nicht als allgemeine Betreiberpflicht ausgegeben. | test_native: vollständige KEV-Mitgliedschaft und dynamische Stale-Kennzeichnung |
| A16-062 | FIRST EPSS integriert. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-063 | EPSS über Envoy bezogen. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-064 | TLS-Zertifikate validiert. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-065 | EPSS-Tages-CSV unterstützt. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-066 | EPSS-Datum erhalten. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-067 | EPSS-Modellversion erhalten. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-068 | EPSS-Score korrekt. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-069 | EPSS-Percentile korrekt. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-070 | Wertebereich 0 bis 1 validiert. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-071 | Fehlende EPSS-Werte nicht als 0 behandelt. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-072 | Veralteter EPSS-Stand kenntlich gemacht. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-073 | EPSS-Historie vorhanden. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-074 | Modellversionswechsel nachvollziehbar. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-075 | Keine unnötigen täglichen Massenrevisionen. | test_epss/test_native/test_container: FIRST, Decimal, Gzip, Vollständigkeit und Historie |
| A16-076 | Ubuntu-Sicherheitsinformationen verarbeitet. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-077 | Ubuntu-Release erhalten. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-078 | Ubuntu-Paketstatus erhalten. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-079 | Quellpakete berücksichtigt. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-080 | Vollständige Ubuntu-Fixversionen erhalten. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-081 | Ubuntu-Backportversionen nicht verkürzt. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-082 | Kein vorzeitiger Versionsvergleich. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-083 | OSV-Aliase verarbeitet. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-084 | OSV-Ökosystem erhalten. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-085 | OSV-Paketidentität erhalten. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-086 | OSV-Versionsbereiche erhalten. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-087 | Introduced, Fixed, Last affected und Limit erhalten. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-088 | OSV-Git-Ranges erhalten. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-089 | Withdrawn-Status berücksichtigt. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-090 | Keine erfundenen PURLs. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-091 | Keine erfundenen CPEs. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-092 | NVD-CPE-Evidenz berücksichtigt. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-093 | NVD-Konfigurationslogik nicht verfälscht. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-094 | CNA-Affected-Daten berücksichtigt. | test_normalize/test_native: Original-Releases/Versionen/Ökosysteme und Logikbäume |
| A16-095 | Keine direkte Matchingentscheidung. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-096 | Keine Serverbetroffenheit behauptet. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-097 | Keine Findings erzeugt. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-098 | Keine Findings verändert. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-099 | Keine Inventarsnapshots verändert. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-100 | Keine administrativen Serverdaten verändert. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-101 | Keine Gruppen verändert. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-102 | Keine Primärgruppen verändert. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-103 | Keine Sortierungen verändert. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-104 | Keine Benutzer-ACLs verändert. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-105 | Eingeschränkte Datenbankrolle verwendet. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-106 | Keine PostgreSQL-Superuser-Rechte. | Native Permissions und Runtime-Sicherheitsnegativtests |
| A16-107 | Enrichment-Revisionen unveränderlich. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-108 | Input-Fingerprint deterministisch. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-109 | Regelversion gespeichert. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-110 | Historische Revisionen erhalten. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-111 | Keine unnötigen Duplikatrevisionen. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-112 | Current-Pointer transaktionssicher. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-113 | Konkurrenzsichere Worker. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-114 | Lease-Verhalten korrekt. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-115 | Retry-Verhalten korrekt. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-116 | Workerabsturz wiederaufnehmbar. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-117 | PostgreSQL-Ausfälle behandelt. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-118 | Outbox-Ereignisse transaktional. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-119 | Keine vollständigen Payloads in Outbox. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-120 | Keine unnötigen EPSS-bedingten Matching-Massenjobs. | test_native: Immutable, Pointer, Koaleszierung, Fencing und Restore |
| A16-121 | Keine Secrets in Logs. | Schlussprüfungen und Abnahmebericht |
| A16-122 | Keine direkte Egress-Umgehung. | Schlussprüfungen und Abnahmebericht |
| A16-123 | Unit-Tests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-124 | PostgreSQL-Integrationstests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-125 | Identitätstests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-126 | CVSS-Tests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-127 | KEV-Tests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-128 | EPSS-Tests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-129 | Ubuntu-Tests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-130 | OSV-Tests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-131 | Konflikttests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-132 | Historientests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-133 | Konkurrenztests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-134 | Sicherheitstests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-135 | Recovery-Tests erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-136 | Performance-Baseline dokumentiert. | Schlussprüfungen und Abnahmebericht |
| A16-137 | Ende-zu-Ende-Test erfolgreich. | Schlussprüfungen und Abnahmebericht |
| A16-138 | Dokumentation vollständig. | Schlussprüfungen und Abnahmebericht |
| A16-139 | Übergabe an Phase 17 vorbereitet. | Schlussprüfungen und Abnahmebericht |
| A16-140 | Keine unzulässigen Architekturänderungen. | Schlussprüfungen und Abnahmebericht |

## ENR-Invarianten

| ID | Regel | Nachweis |
|---|---|---|
| ENR-01 | Nur persistierte Quellrevisionen aus Phase 15 werden fachlich zusammengeführt | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-02 | Originale Rohdaten bleiben unverändert | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-03 | Keine neue direkte CVE-Quellensynchronisierung außerhalb des vereinbarten EPSS-Imports | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-04 | Keine automatische Serverinventarisierung | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-05 | Keine Verbindung zu verwalteten Servern | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-06 | Keine Änderung von Inventarsnapshots | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-07 | Keine Änderung administrativer Serverdaten | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-08 | Keine Gruppenänderungen | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-09 | Keine Primärgruppenänderungen | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-10 | Keine Sortieränderungen | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-11 | Keine ACL-Änderungen | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-12 | Keine Finding-Erzeugung | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-13 | Keine CVE-Server-Matchingentscheidung | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-14 | CVE-Identitäten bleiben eindeutig | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-15 | Advisory-Identitäten bleiben eigenständig | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-16 | Aliasbeziehungen werden typisiert | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-17 | Keine Verschmelzung mehrerer CVEs durch gemeinsame Advisories | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-18 | Keine erfundene CVE-ID | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-19 | Keine Identitätsentscheidung durch bloße Textähnlichkeit | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-20 | Quellenpriorisierung ist feldbezogen | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-21 | Jede relevante Aussage besitzt Provenienz | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-22 | Quellenkonflikte werden nicht stillschweigend unterdrückt | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-23 | Offizielle CVE-Status werden beachtet | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-24 | REJECTED-Records bleiben historisch erhalten | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-25 | CVSS-Versionen bleiben unterscheidbar | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-26 | CVSS-Vektoren werden validiert | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-27 | Mehrere CVSS-Bewertungen bleiben erhalten | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-28 | Fehlender CVSS-Wert bedeutet nicht Score 0 | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-29 | Keine ungetestete eigene CVSS-Formel | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-30 | Keine frei erfundene Gesamtrisikozahl | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-31 | Keine serverbezogene Environmental-Bewertung | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-32 | KEV wird auf einen gültigen Katalogstand bezogen | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-33 | Unvollständiger KEV-Katalog erzeugt keine falschen Negativaussagen | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-34 | KEV bedeutet nicht nachgewiesene Kompromittierung eines konkreten Servers | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-35 | FIRST EPSS wird offiziell und sicher bezogen | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-36 | EPSS-Tagesdaten werden historisiert | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-37 | EPSS Score und Percentile bleiben getrennt | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-38 | EPSS-Werte liegen zwischen 0 und 1 | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-39 | Fehlende EPSS-Werte werden nicht als 0 behandelt | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-40 | EPSS-Modellversionen werden erhalten | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-41 | Unvollständige EPSS-Tagesstände werden nicht aktiviert | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-42 | Keine unnötigen täglichen Massenrevisionen | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-43 | Ubuntu-Releasekontext bleibt erhalten | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-44 | Ubuntu-Fixversionen bleiben vollständig | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-45 | Keine naive SemVer-Konvertierung von Ubuntu-Paketen | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-46 | OSV-Ökosysteme bleiben erhalten | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-47 | OSV-Versionsbereiche bleiben vollständig | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-48 | Git-Ranges werden nicht als normale Paketversionen behandelt | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-49 | Keine erfundenen CPEs | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-50 | Keine erfundenen PURLs | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-51 | Keine automatische Versionsbewertung gegen installierte Pakete | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-52 | Enrichment-Revisionen sind unveränderlich | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-53 | Regelversionen werden gespeichert | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-54 | Quellrevisionen werden referenziert | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-55 | Wiederholungen sind idempotent | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-56 | Current-Pointer sind transaktionssicher | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-57 | PostgreSQL bleibt das einzige Datenbanksystem | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-58 | Kein Redis | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-59 | Kein zusätzlicher Message Broker | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-60 | Bestehende PostgreSQL-Worker werden verwendet | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-61 | Leases und Retries sind begrenzt | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-62 | Transactional Outbox wird verwendet | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-63 | Keine vollständigen Rohpayloads in Outbox-Ereignissen | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-64 | Kein Docker-Socket | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-65 | Keine unnötigen öffentlichen Ports | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-66 | Keine unnötigen Containerprivilegien | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-67 | EPSS-Egress ausschließlich über Envoy | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-68 | TLS-Zertifikatsprüfung ist verpflichtend | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-69 | Kein direkter Egress-Fallback | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-70 | Minimale Datenbankrechte | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-71 | Keine PostgreSQL-Superuser-Rechte | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-72 | Keine Secrets in Logs | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-73 | Sicherheits- und Konkurrenztests sind verpflichtend | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-74 | Keine Git-Commits ohne Auftrag | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |
| ENR-75 | Kein Git-Push ohne Auftrag | Quellenpolitik, native Constraints/Rechte, Unit-/Pipeline-/Runtime-Prüfungen und Abnahme |

## Befehle

make check; make cve-enricher-check; make cve-enricher-integration; make cvss-test;
make epss-test; make cve-enricher-security; make cve-enricher-concurrency;
make cve-enricher-performance; make cve-enricher-e2e. Docker bei Bedarf mit CVE_DOCKER_SUDO=1.
Private Nachweise: .runtime/test-reports/phase-16-*.
