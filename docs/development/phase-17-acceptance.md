# Abnahme Phase 17

Stand 08.11.2026: alle 45 Aufträge abgeschlossen; die 176 verpflichtenden Prüfpunkte
sind in der [Testmatrix](../testing/phase-17-test-matrix.md) einzeln zugeordnet.

cve-matcher 0.17.0, cve_common 0.7.0 und Migration 00023_matching_engine sind aktiv.
Die zehn eigenen Dienste sind gesund. Alle zuvor vorhandenen Service-Pythonpakete und sämtliche
vorherigen Migrationen wurden nicht geändert: 173 zuvor erfasste Python-Dateien hashgleich.
76 Fach-/Administrations-/Inventar-/CVE-Tabellen und die n8n-Datenbank bleiben datenidentisch.
Envoy-Bindungen, Policy und SMTP sowie die vier fremden Nextcloud-Container sind unverändert.
Kein Matching-Ergebnis oder Finding wurde in die normale Umgebung eingespeist.
Vor der Migration wurden beide Datenbanken unter .runtime/phase17-pre-migration gesichert.

| Prüfung | Erfolgreiche Fälle |
|---|---:|
| Matching: native dpkg/RPM-/SemVer-Vergleiche | 226 |
| Matching: Fachregeln, Coverage, Kernel, CPE und große Inventare | 55 |
| Matching: native PostgreSQL-/Worker-/Revisions-/Rechteprüfungen | 27 |
| Matching: tatsächliches Image, Netzwerk, PG-Ausfall, SIGKILL, Guard und Dateihashes | 8 |
| Regression standard | 551 |
| Regression database | 189 |
| Regression importer | 120 |
| Regression enricher | 78 |
| Regression automation | 29 |
| Regression inventory_processor | 36 |
| Regression infrastructure | 40 |
| Gesamt, ohne mehrfach gezählte Testfälle | 1359 |

`make check` ist erfolgreich: Ruff, Formatierung, striktes Mypy, 551 Standardfälle,
Repository-/Schema-/Compose-Validierung und Secretprüfung. Mypy umfasst 351 Quelldateien;
die Secret-Baseline wurde nicht verändert. Die Matching-Nachweise sind eine Fall-ID-Union
aus dem Gesamtlauf und gezielten Nachprüfungen; Wiederholungen zählen nur einmal. Es wird
kein einzelner Lauf mit 316 Fällen behauptet.

Messungen: 100 CVEs über mehrere native Testbestände in
10.617 Sekunden. 10000 gleichzeitig installierte
Pakete in 1.190 Sekunden; vom Python-Tracer gemessene
Spitzenallokation 29.48 MiB. Dies ist eine
reproduzierbare Testbaseline, keine universelle Produktionskapazitätszusage. Der Queryplan
für strukturierte Kandidatenschlüssel nutzt den vorhandenen B-Tree-Index.

Nachweise (lokale, ignorierte Dateien unter .runtime/test-reports):
phase-17-test-summary.json, phase-17-matching.xml, phase-17-final-targeted.xml,
phase-17-final-engine.xml, phase-17-final-check.log, phase-17-final-mypy.log,
phase-17-db-jobs-regression.log, phase-17-source-regression.log,
phase-17-worker-inventory-regression.log, phase-17-infra-regression.log,
phase-17-live-verification.json und phase-17-backup-path.txt.

Fachliche Grenzen sind ausdrücklich geprüft: ausschließlich belegte Identität, passender
Release/Source-Paketstand und unterstützte Vergleichssemantik tragen definitive Aussagen.
Ubuntu-OVAL, Container-SBOM, CPE-Zuordnung und Git-Abstammung werden nicht erfunden.
Die Laufzeit beansprucht deshalb keine vollständige globale Negativabdeckung für Inventar 1.1.
Keine Finding-Schreibrechte, keine Finding-Erzeugung oder -Schließung; keine Zustellroute
für Phase 18 eingerichtet. Es wurden keine Git-Commits oder Pushes erstellt.
