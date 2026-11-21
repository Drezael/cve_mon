# Status Phase 18

Abgeschlossen am 08.11.2026: 45 von 45 Aufträgen; 164 Kriterien einzeln in der
[Testmatrix](../testing/phase-18-test-matrix.md), Ergebnisse in der [Abnahme](phase-18-acceptance.md).
Keine offenen verpflichtenden Aufgaben.

| Auftrag | Inhalt | Status |
|---|---|---|
| T18.01.01 | Repository und Finding-Architektur analysieren | completed |
| T18.01.02 | Identität und Episodenmodell | completed |
| T18.01.03 | Finding-State-Machine | completed |
| T18.01.04 | Fixnachweis und Reopening-Regeln | completed |
| T18.01.05 | Sicherheit, API und Phase-19-Verträge | completed |
| T18.02.01 | Datenbankschema und Rollen prüfen | completed |
| T18.02.02 | Stabile Findings und Beobachtungen | completed |
| T18.02.03 | Episoden und Zustandsverlauf | completed |
| T18.02.04 | Triage-, Ausnahme- und Fristenmodelle | completed |
| T18.02.05 | Migrationen, Constraints und Berechtigungen | completed |
| T18.03.01 | Finding-Service integrieren | completed |
| T18.03.02 | Finding-Jobhandler | completed |
| T18.03.03 | Matching-Events idempotent übernehmen | completed |
| T18.03.04 | Finding-Eröffnung und Wiedererkennung | completed |
| T18.03.05 | Worker- und Deduplizierungstests | completed |
| T18.04.01 | Lifecycle-State-Machine | completed |
| T18.04.02 | Technische Behebungserkennung | completed |
| T18.04.03 | Unvollständige und veraltete Ergebnisse | completed |
| T18.04.04 | Reopening und Episodenwechsel | completed |
| T18.04.05 | Lifecycle- und Fixnachweistests | completed |
| T18.05.01 | Triage und Notizen | completed |
| T18.05.02 | Zuständigkeitsverwaltung | completed |
| T18.05.03 | Fehlalarmprüfung | completed |
| T18.05.04 | Risikoausnahmen und Maßnahmen | completed |
| T18.05.05 | Triage-, Audit- und RBAC-Tests | completed |
| T18.06.01 | Versionierte Priorisierung | completed |
| T18.06.02 | Richtlinienbasierte Fristen | completed |
| T18.06.03 | CVSS-/KEV-/EPSS-Änderungen | completed |
| T18.06.04 | Überfälligkeit und Ausnahmeablauf | completed |
| T18.06.05 | Prioritäts- und SLA-Tests | completed |
| T18.07.01 | Geschützte Finding-Lese-API | completed |
| T18.07.02 | Geschützte Verwaltungs-API | completed |
| T18.07.03 | RBAC und Gruppen-Scope | completed |
| T18.07.04 | Dashboard-Verträge und Kennzahlen | completed |
| T18.07.05 | API- und Sicherheitstests | completed |
| T18.08.01 | Docker-Integration und Härtung | completed |
| T18.08.02 | Logging, Metriken und Health | completed |
| T18.08.03 | Performance und Konkurrenzsicherheit | completed |
| T18.08.04 | Recovery und Historienintegrität | completed |
| T18.08.05 | Betriebs- und Sicherheitstests | completed |
| T18.09.01 | Automatisierte Testsuite | completed |
| T18.09.02 | Ende-zu-Ende-Lifecycle-Test | completed |
| T18.09.03 | Kritische Grenzfälle und Konkurrenz | completed |
| T18.09.04 | Technische Dokumentation | completed |
| T18.09.05 | Gesamtabnahme | completed |

Die Reihenfolge und Voraussetzungen stehen im Plan (nur lokal archiviert); jeder Block setzt
den vorherigen sowie die bestehende Plattform aus Phase 17 voraus. Details und Ergebnisse:

| Auftragsblock | Dateien und konkrete Ergebnisse | Prüfung |
|---|---|---|
| T18.01 | architecture/finding-management.md; findings/identity.md, lifecycle.md, resolution-policy.md, reopening.md; phase-18-analysis.md | Architektur-/Quellstand und Phase-0-Verträge abgeglichen |
| T18.02 | Migrationen 00024/00025; database/finding-data-model.md | Datenhaltung, eigene Rolle, immutable Historien, CAS, Actor- und Auditgrenzen nativ geprüft |
| T18.03 | cve_findings/service.py, repository.py, main.py, contracts.py | Event-Receipts, Publikationsversionen, Lease-Fence und konkurrierende Worker geprüft |
| T18.04 | cve_findings/rules.py; findings/lifecycle.md, resolution-policy.md, reopening.md | Fixnachweis, Stale, Unsicherheit, Resolution und Episodenwechsel geprüft |
| T18.05 | 00025_finding_commands; cve_api/findings/; findings/triage.md, exceptions.md, audit-history.md | Triage, Notizen, Zuweisung, Fehlalarm, Ausnahmen und vertrauenswürdiger Actor geprüft |
| T18.06 | Policy, priority_history, deadlines, escalations; findings/prioritization.md, deadlines.md | CVSS/KEV/EPSS getrennt, explizite Fristen, kein stiller Reset, idempotente Eskalation geprüft |
| T18.07 | API router.py/service.py; finding-management.openapi.yaml; permission-catalog.yaml, role-matrix.yaml | Auth, CSRF, MFA, ETag, IDOR-Scope, Listen/Details/Historie/Aggregate über HTTPS geprüft |
| T18.08 | compose.yml; Dockerfile; scripts/cve_findings/manage.py; operations/finding-worker.md, finding-recovery.md | Rootless, Read-only, Namespace-Guard, kein Egress, PG-Ausfall, SIGKILL und Quellenparität geprüft |
| T18.09 | tests/findings/; Testmatrix, Abnahme, Übergabe | Fachliche Gesamtsuite, Regressionen, Performance und aktive Umgebung geprüft |

Datenbank: Schema findings mit Findings, Episoden/Closures, Beobachtungen, Event-Receipts,
Audit, Notizen, Zuweisungen, Reviews, Ausnahmen/Entscheidungen, Maßnahmen, Policyversionen,
Prioritäten, Fristen und Eskalationen. findings_writer besitzt nur technische Fachschreibrechte;
api_security verwendet autorisierte Kommandofunktionen. Vorhandene administrative Tabellen
werden nicht vom Worker geschrieben. API `/api/v1/findings` nutzt bestehende finding:read/
finding:update-Rechte und vier neue privilegierte Adminrechte. Technische und manuelle
Outbox-Producer bleiben getrennt. Alle neuen Events sind kompakte Referenzen.

Migrationen und beide Dienste sind aktiviert. Elf eigene Dienste gesund, keine Test-Findings
in der normalen Umgebung; Backup und Fingerprintnachweis liegen lokal vor. Details zu
Testergebnissen, Sicherheits-/Konkurrenz-/Recovery-/Performanceprüfungen und Schutz bestehender
Daten stehen in der Abnahme. Keine offenen Probleme; Abschlussdatum 08.11.2026.
