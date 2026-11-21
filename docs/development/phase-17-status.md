# Status Phase 17

Phase 17 ist abgeschlossen. Alle 45 Aufträge wurden umgesetzt und geprüft. Phase 18 wurde nicht begonnen.

cve-matcher 0.17.0 läuft als zehnter eigener Dienst gesund. DB-Head:
00023_matching_engine. Kein automatischer Backfill oder Import beim Start. Die normale
Umgebung hat weiterhin keine Inventare, CVEs oder Findings; Tests verwenden eigene Projekte.

| Auftrag | Inhalt | Status |
|---|---|---|
| T17.01.01 | Repository und Matching-Grundlagen analysieren | abgeschlossen |
| T17.01.02 | Ergebnisstatus und Entscheidungssemantik | abgeschlossen |
| T17.01.03 | Matching-Pipeline und Evidenzhierarchie | abgeschlossen |
| T17.01.04 | Versions- und Distributionsregeln | abgeschlossen |
| T17.01.05 | Sicherheit, Coverage und Finding-Übergabe | abgeschlossen |
| T17.02.01 | Matching-Datenbankmodelle prüfen | abgeschlossen |
| T17.02.02 | Läufe, Eingaben und Kandidaten modellieren | abgeschlossen |
| T17.02.03 | Einzelmatches, Revisionen und Evidenz | abgeschlossen |
| T17.02.04 | Current-Pointer, Coverage und Indizes | abgeschlossen |
| T17.02.05 | Migrationen, Constraints und Rechte | abgeschlossen |
| T17.03.01 | Matching-Service integrieren | abgeschlossen |
| T17.03.02 | Jobhandler und Änderungsereignisse | abgeschlossen |
| T17.03.03 | Inventarbasierte Kandidatenauswahl | abgeschlossen |
| T17.03.04 | CVE-basierte Kandidatenauswahl | abgeschlossen |
| T17.03.05 | Job-, Kandidaten- und Konkurrenztests | abgeschlossen |
| T17.04.01 | Paket- und Ökosystemidentität | abgeschlossen |
| T17.04.02 | Distribution, Release und Quellpakete | abgeschlossen |
| T17.04.03 | Architektur und Mehrfachversionen | abgeschlossen |
| T17.04.04 | Kernel und Docker | abgeschlossen |
| T17.04.05 | Identitäts- und Kontexttests | abgeschlossen |
| T17.05.01 | Debian-/Ubuntu-Versionsvergleich | abgeschlossen |
| T17.05.02 | RPM-EVR-Versionsvergleich | abgeschlossen |
| T17.05.03 | SemVer- und Ökosystemadapter | abgeschlossen |
| T17.05.04 | OSV-Versionbereiche | abgeschlossen |
| T17.05.05 | Versionsvergleichs-Regressionssuite | abgeschlossen |
| T17.06.01 | Ubuntu-Sicherheitsstatus und Backports | abgeschlossen |
| T17.06.02 | CNA-Affected-Regeln | abgeschlossen |
| T17.06.03 | CPE-Namen und Versionsgrenzen | abgeschlossen |
| T17.06.04 | NVD-Konfigurationsbaum | abgeschlossen |
| T17.06.05 | Ubuntu-, CNA- und NVD-Tests | abgeschlossen |
| T17.07.01 | Einheitliche Entscheidungsengine | abgeschlossen |
| T17.07.02 | Unsicherheit, Konflikte und Gründe | abgeschlossen |
| T17.07.03 | Server-CVE-Aggregation | abgeschlossen |
| T17.07.04 | Revisionen, Current-Pointer und Outbox | abgeschlossen |
| T17.07.05 | Entscheidungs- und Revisionstests | abgeschlossen |
| T17.08.01 | Kandidatenindizes und Performance | abgeschlossen |
| T17.08.02 | Worker-Recovery und Reconciliation | abgeschlossen |
| T17.08.03 | Sicherheitsisolation | abgeschlossen |
| T17.08.04 | Logging, Health und Metriken | abgeschlossen |
| T17.08.05 | Betriebs-, Performance- und Sicherheitstests | abgeschlossen |
| T17.09.01 | Automatisierte Testsuite | abgeschlossen |
| T17.09.02 | Ende-zu-Ende-Test | abgeschlossen |
| T17.09.03 | Fachliche Grenzfälle und Konkurrenz | abgeschlossen |
| T17.09.04 | Dokumentation | abgeschlossen |
| T17.09.05 | Gesamtabnahme | abgeschlossen |

Die Quellen-/Abdeckungsgrenzen sind Teil der implementierten Unsicherheitsregeln:
Ubuntu-API ohne verifizierte OVAL-Evidenz liefert keine definitive Entwarnung; OSV-GIT
benötigt einen vorhandenen Commitgraph; Container ohne SBOM erhalten keine erfundene
Paketliste; CPE ohne belegte Inventarzuordnung bleibt unbekannt. Komponenten-negativ
ist keine globale Serverentwarnung.

[Abnahme](phase-17-acceptance.md), [Testmatrix](../testing/phase-17-test-matrix.md),
[Übergabe Phase 18](phase-17-handover.md).
