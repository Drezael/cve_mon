# Phase 15 – Aufgabenstatus

Status: completed; alle 45 Aufträge umgesetzt und lokal geprüft. Stand: 08.11.2026.

| Auftrag | Aufgabe | Status | Implementierung/Nachweis |
|---|---|---|---|
| T15.01.01 | Repository, Datenbank und vorhandene Importarchitektur analysieren | completed | Bestandsanalyse, Quellenverträge und ADR-0033 |
| T15.01.02 | Quellenregister und verbindliche Quellenverträge spezifizieren | completed | Bestandsanalyse, Quellenverträge und ADR-0033 |
| T15.01.03 | Importpipeline und Zustandsmodell spezifizieren | completed | Bestandsanalyse, Quellenverträge und ADR-0033 |
| T15.01.04 | Initialimport, Deltaimport und Reconciliation spezifizieren | completed | Bestandsanalyse, Quellenverträge und ADR-0033 |
| T15.01.05 | Threat Model und Phase-16-Abgrenzung festlegen | completed | Bestandsanalyse, Quellenverträge und ADR-0033 |
| T15.02.01 | Bestehende CVE-Datenbankmodelle prüfen | completed | Migration 00020, native PostgreSQL-Rechte/FKs/Revisionen |
| T15.02.02 | Quellenregister und Importläufe vervollständigen | completed | Migration 00020, native PostgreSQL-Rechte/FKs/Revisionen |
| T15.02.03 | JSONB-Rohrecords und unveränderliche Revisionen implementieren | completed | Migration 00020, native PostgreSQL-Rechte/FKs/Revisionen |
| T15.02.04 | Identitäten, Aliase und Synchronisationscursor implementieren | completed | Migration 00020, native PostgreSQL-Rechte/FKs/Revisionen |
| T15.02.05 | Migrationen, Datenintegrität und Berechtigungen testen | completed | Migration 00020, native PostgreSQL-Rechte/FKs/Revisionen |
| T15.03.01 | `cve-importer` in die bestehende Servicearchitektur integrieren | completed | Servicebasis, Transport, Parser, Compose/Envoy; test_transport/test_container |
| T15.03.02 | Importjobs und Quellhandler registrieren | completed | Servicebasis, Transport, Parser, Compose/Envoy; test_transport/test_container |
| T15.03.03 | Geschützten HTTP-Client über Envoy implementieren | completed | Servicebasis, Transport, Parser, Compose/Envoy; test_transport/test_container |
| T15.03.04 | Gemeinsamen Downloader und Parser-Schutz implementieren | completed | Servicebasis, Transport, Parser, Compose/Envoy; test_transport/test_container |
| T15.03.05 | HTTP-, Egress-, Worker- und Sicherheitstests durchführen | completed | Servicebasis, Transport, Parser, Compose/Envoy; test_transport/test_container |
| T15.04.01 | Offiziellen cvelistV5-Quellenadapter implementieren | completed | adapters.cveproject, Offline-CVE-Schemas; test_validation/test_pipeline |
| T15.04.02 | Vollständigen Erstimport implementieren | completed | adapters.cveproject, Offline-CVE-Schemas; test_validation/test_pipeline |
| T15.04.03 | Inkrementelle Delta-Synchronisierung implementieren | completed | adapters.cveproject, Offline-CVE-Schemas; test_validation/test_pipeline |
| T15.04.04 | CVE-Formatversionen und Recordstatus behandeln | completed | adapters.cveproject, Offline-CVE-Schemas; test_validation/test_pipeline |
| T15.04.05 | CVEProject-Import umfassend testen | completed | adapters.cveproject, Offline-CVE-Schemas; test_validation/test_pipeline |
| T15.05.01 | NVD-Client und API-Konfiguration implementieren | completed | adapters.nvd, persistente Budgets, Fenster/Pagination; test_pipeline/test_transport |
| T15.05.02 | Pagination und Initialimport implementieren | completed | adapters.nvd, persistente Budgets, Fenster/Pagination; test_pipeline/test_transport |
| T15.05.03 | Inkrementelle Änderungsfenster implementieren | completed | adapters.nvd, persistente Budgets, Fenster/Pagination; test_pipeline/test_transport |
| T15.05.04 | NVD-Records versioniert speichern | completed | adapters.nvd, persistente Budgets, Fenster/Pagination; test_pipeline/test_transport |
| T15.05.05 | NVD-Pagination, Rate-Limits und Recovery testen | completed | adapters.nvd, persistente Budgets, Fenster/Pagination; test_pipeline/test_transport |
| T15.06.01 | CISA-KEV-Quellenadapter implementieren | completed | adapters.kev/ubuntu; Katalog-/Statusströme und native Pipelinefälle |
| T15.06.02 | KEV-Kataloghistorie und Vollständigkeitsabgleich implementieren | completed | adapters.kev/ubuntu; Katalog-/Statusströme und native Pipelinefälle |
| T15.06.03 | Ubuntu-Security-Quellenadapter implementieren | completed | adapters.kev/ubuntu; Katalog-/Statusströme und native Pipelinefälle |
| T15.06.04 | Ubuntu-Daten revisionssicher speichern | completed | adapters.kev/ubuntu; Katalog-/Statusströme und native Pipelinefälle |
| T15.06.05 | CISA- und Ubuntu-Integrationstests durchführen | completed | adapters.kev/ubuntu; Katalog-/Statusströme und native Pipelinefälle |
| T15.07.01 | OSV-Quellenadapter und Full-Dump-Import implementieren | completed | adapters.osv, Aliase/Provenienz, Dumps/Index; test_pipeline |
| T15.07.02 | Inkrementelle OSV-Änderungen implementieren | completed | adapters.osv, Aliase/Provenienz, Dumps/Index; test_pipeline |
| T15.07.03 | OSV-Aliase und Withdrawn-Status verarbeiten | completed | adapters.osv, Aliase/Provenienz, Dumps/Index; test_pipeline |
| T15.07.04 | Gemeinsame Quellidentität, Provenienz und Qualitätsprüfung vervollständigen | completed | adapters.osv, Aliase/Provenienz, Dumps/Index; test_pipeline |
| T15.07.05 | OSV-, Alias- und Datenqualitätstests durchführen | completed | adapters.osv, Aliase/Provenienz, Dumps/Index; test_pipeline |
| T15.08.01 | Cursorverwaltung, Checkpoints und Reconciliation integrieren | completed | ExecutionContext, Quellleases, persist/finish, Metriken; Recovery/Containerfälle |
| T15.08.02 | Retry, Fehlerklassifikation und Recovery implementieren | completed | ExecutionContext, Quellleases, persist/finish, Metriken; Recovery/Containerfälle |
| T15.08.03 | Transactional Outbox und Quellstatus integrieren | completed | ExecutionContext, Quellleases, persist/finish, Metriken; Recovery/Containerfälle |
| T15.08.04 | Betriebsmetriken und Performanceoptimierung implementieren | completed | ExecutionContext, Quellleases, persist/finish, Metriken; Recovery/Containerfälle |
| T15.08.05 | Docker-, Egress-, Datenbankrechte- und Recovery-Tests durchführen | completed | ExecutionContext, Quellleases, persist/finish, Metriken; Recovery/Containerfälle |
| T15.09.01 | Automatisierte Testsuite zusammenführen | completed | Make/CI, Testmatrix, Betriebsdokumentation, Schlussabnahme |
| T15.09.02 | Ende-zu-Ende-Test aller fünf Datenquellen durchführen | completed | Make/CI, Testmatrix, Betriebsdokumentation, Schlussabnahme |
| T15.09.03 | Langzeit-, Konkurrenz-, Recovery- und Sicherheitstests durchführen | completed | Make/CI, Testmatrix, Betriebsdokumentation, Schlussabnahme |
| T15.09.04 | Technische und betriebliche Dokumentation erstellen | completed | Make/CI, Testmatrix, Betriebsdokumentation, Schlussabnahme |
| T15.09.05 | Phase-15-Gesamtabnahme durchführen | completed | Make/CI, Testmatrix, Betriebsdokumentation, Schlussabnahme |

Die Quell-/Datenbank-/Envoy-/Recovery-Nachweise sind in der [Testmatrix](../testing/phase-15-test-matrix.md) verknüpft.

Abschluss: 120 unterschiedliche Importerfälle nachgewiesen; zusammenhängender 111-Fall-Lauf
plus gezielte Schlussläufe für nachfolgende Korrekturen und Ergänzungen. 551 Standardfälle
sowie 382 zusätzliche Regressionsfälle bestanden. Native Migration, Rollen, Envoy, Recovery,
Backup/Restore, Ressourcen und lokale Aktivierung geprüft. Acht Dienste gesund;
keine normalen Importdaten oder administrativen Änderungen. Details in der [Abnahme](phase-15-acceptance.md).
