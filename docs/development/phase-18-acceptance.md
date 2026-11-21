# Abnahme Phase 18

Stand 08.11.2026: alle 45 Aufträge abgeschlossen. Die 164 verpflichtenden Kriterien aus
T18.09.05 sind einzeln in der [Testmatrix](../testing/phase-18-test-matrix.md) zugeordnet.
[Status](phase-18-status.md), [Architektur](../architecture/finding-management.md) und
[Übergabe an Phase 19](phase-18-handover.md) beschreiben den ausgelieferten Stand.

cve-findings 0.18.0 und cve-api 0.18.0 sind mit cve_common 0.7.0 aktiviert. Head ist
00025_finding_commands; Migrationen 00024/00025 erweitern den Bestand datenhaltend.
Alle elf eigenen Dienste sind gesund. Vor der Migration wurden beide Datenbanken unter
.runtime/phase18-pre-migration gesichert. 88 bestehende Fach-/Administrations-/Inventar-/
CVE-/Matching-Tabellen bleiben datenidentisch. Nur die vorgesehenen vier zusätzlichen
Adminberechtigungen verändern den bestehenden Berechtigungskatalog und seine Rollenzuordnung.
Die n8n-Datenbank, Envoy-Bindungen und -Policy sowie die vier fremden Nextcloud-Container
sind unverändert. Alle bestehenden eigenen Container außer der aktualisierten API behalten
ihre IDs. Es wurden keine synthetischen Finding-, Matching- oder Inventardaten in die normale
Umgebung übernommen und keine Testbenutzer angelegt.

179 zuvor erfasste Python-Dateien sind hashgleich. Vier notwendige bestehende API-Dateien
registrieren Finding-Router, Auth-Gate, Version und privilegierte Berechtigungen. Alte Worker,
cve_common und alle vorherigen Migrationen bleiben unverändert. Die tatsächlichen Images
enthalten dieselben Quellen wie das Workspace: sieben Finding- und 81 API-Pythondateien;
auch das von der API verwendete Finding-Paket wurde separat verglichen.

| Prüfung | Erfolgreiche Fälle |
|---|---:|
| Finding-Regeln: Lifecycle, Fixnachweis, Priorität, Fristen, Ausnahmen | 38 |
| Finding: native PostgreSQL-/Identitäts-/Event-/Lease-/Rechte-/Konkurrenz-/Lastprüfungen | 33 |
| Finding: API, Auth, Scope, Triage, Fehlalarm, Resolution, Ausnahmen, SLA, tatsächliches HTTPS | 13 |
| Finding: echtes Image, Netzwerk, Readiness, SIGKILL, PG-Ausfall, Guard und Recovery | 8 |
| Regression: Standard | 551 |
| Regression: Datenbank | 189 |
| Regression: Jobs/Outbox | 29 |
| Regression: Authentifizierung | 56 |
| Regression: Autorisierung | 37 |
| Regression: Serververwaltung | 53 |
| Regression: Matching | 316 |
| Regression: Enrichment | 78 |
| Regression: Inventarverarbeitung | 36 |
| Regression: Infrastruktur | 40 |
| Regression: bestehende API-/Service-Container | 11 |
| Gesamt ohne mehrfach gezählte Testfälle | 1488 |

`make check` ist erfolgreich: Ruff, Formatierung, striktes Mypy für 369 Quelldateien,
551 Standardfälle, Repository-/Schema-/Compose-Validierung und Secretprüfung. Die bestehende
Secret-Baseline wurde nicht erweitert. Die API-Vertragsdatei wurde zusätzlich mit
openapi-spec-validator geprüft. Der vollständige Finding-Lauf umfasst 92 erfolgreiche Fälle.

Performance-Baseline: 100 neue Findings einschließlich Episoden, Priorität, Audit und
Outbox in 1.122 Sekunden im isolierten nativen Testbestand. Dies ist eine lokale Testmessung,
keine allgemeine Kapazitätszusage. Zwei und vier konkurrierende Verarbeiter erzeugen dieselbe
stabile Identität; verlorene Leases rollen die gesamte Fachänderung zurück. SIGKILL und
PostgreSQL-Ausfall wurden am tatsächlichen Container geprüft. Nach Neustart ist der neue
Namespace-Guard zwingend; fehlender oder falscher Proof hält Readiness und Worker geschlossen.

Sicherheit: eigene Rolle ohne Inventar-, CVE-, Enrichment-, Matching- oder administrative
Schreibrechte; API ohne direkte Finding-Schreibrechte. Autorisierte Kommandofunktionen prüfen
Sitzung, aktuelle Rollen/ACLs, MFA und erwartete Row-Version. Listen und Aggregationen filtern
Objektberechtigungen vor Zählung/Pagination. Actor und Zeit stammen ausschließlich vom Server.
Notes sind Klartext. Ungültige Sortierungen und unbekannte Payload-Felder werden abgelehnt.
Die Netzwerkpolicy erlaubt nur eigene PostgreSQL-Kommunikation, DNS und lokalen Healthverkehr.
Kein Hostport, Docker-Socket, direkter Internet- oder Zielserverzugriff. HTTPS liefert ohne
Sitzung 401; im isolierten End-to-End-Test funktioniert die echte authentifizierte Abfrage.
Keine externen Finding-Zustellrouten wurden aktiviert.

Fachliche Grenzen sind Teil der Abnahme: Unknown, fehlende oder veraltete Daten sowie
Teilabdeckung sind kein Fix. Der aktuelle Phase-17-/Inventory-1.1-Vertrag belegt keine globale
Negativabdeckung. Automatische Resolution ist deshalb standardmäßig deaktiviert und verlangt
explizite Policy, Frische und vollständigen Negativnachweis. Manuelle Fehlalarm-Schließung ist
eine begründete autorisierte Entscheidung mit gebundener Evidenz, keine technische Reparatur.
Eine bloße Risikoänderung eröffnet keine neue Episode. Ausnahmen bleiben endlich, scoped und
widerrufbar. Ohne genehmigte SLA-Regel entsteht keine Frist; CISA dueDate ist keine erfundene
rechtliche Verpflichtung. Benachrichtigungen und Dashboard-Oberflächen folgen später.

Lokale Laufnachweise unter .runtime/test-reports:
phase-18-findings-final.xml und .log, phase-18-final-api.xml, phase-18-final-check.log,
phase-18-database-jobs-regression.log, phase-18-authz-regression.log,
phase-18-matching-enrichment-regression.log, phase-18-runtime-regression.log,
phase-18-live-verification.json und .log, phase-18-live-migration.log,
phase-18-backup.log und phase-18-backup-path.txt. Die abschließende Lastmessung steht in
phase-18-findings-final.xml; phase-18-test-summary.json fasst die Nachweise zusammen.
Wiederholte Läufe werden nicht mehrfach gezählt.
Keine Git-Commits oder Pushes erstellt. Keine offenen verpflichtenden Phase-18-Aufgaben.
