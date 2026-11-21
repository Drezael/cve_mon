# Phase 14 – Einzelaufträge

Status: completed. Alle 45 Aufträge lokal implementiert und abgenommen; 934 unterschiedliche relevante Tests nachgewiesen.

Plan (nur lokal archiviert) · [Abnahme](phase-14-acceptance.md) · [Dateien](phase-14-files.json)

Revision: 00019. Runtime-Rolle: inventory_processor. Verwaltungsrollen erhalten keine zusätzlichen Schreibrechte.
Neue Verarbeitungsschreibbereiche: Snapshot/Kindtabellen, submission_processing, gefencete Jobs, Audit und Outbox.
Current-Pointer ausschließlich über inventory.select_current. Herkunft, Originale und administrative Tabellen unverändert.

| Auftrag | Titel | Status | Voraussetzung | Ergebnis / Dateien | Prüfung |
|---|---|---|---|---|---|
| T14.01.01 | Bestehende Inventar- und Workerarchitektur analysieren | completed | Bestandsaufnahme | Architektur und Verträge; phase-14-analysis.md; ../architecture/inventory-processor.md; ADR-0032 | Unit-/Schema-/Dokumentprüfungen |
| T14.01.02 | Verarbeitungspipeline und Verantwortlichkeiten spezifizieren | completed | T14.01.01 | Architektur und Verträge; phase-14-analysis.md; ../architecture/inventory-processor.md; ADR-0032 | Unit-/Schema-/Dokumentprüfungen |
| T14.01.03 | Normalisierungsvertrag und Versionierung spezifizieren | completed | T14.01.02 | Architektur und Verträge; phase-14-analysis.md; ../architecture/inventory-processor.md; ADR-0032 | Unit-/Schema-/Dokumentprüfungen |
| T14.01.04 | Snapshot- und Current-Selection-Regeln festlegen | completed | T14.01.03 | Architektur und Verträge; phase-14-analysis.md; ../architecture/inventory-processor.md; ADR-0032 | Unit-/Schema-/Dokumentprüfungen |
| T14.01.05 | Sicherheits-, Fehler- und Integritätsvertrag erstellen | completed | T14.01.04 | Architektur und Verträge; phase-14-analysis.md; ../architecture/inventory-processor.md; ADR-0032 | Unit-/Schema-/Dokumentprüfungen |
| T14.02.01 | Bestehende Datenbankmodelle und Berechtigungen prüfen | completed | T14.01.05 | Revision 00019, inventory/automation/security; database/migrations/versions/00019_inventory_processing.py | 189 Datenbanktests; native Rollen/Immutability |
| T14.02.02 | Snapshot-Grundmodell vervollständigen | completed | T14.02.01 | Revision 00019, inventory/automation/security; database/migrations/versions/00019_inventory_processing.py | 189 Datenbanktests; native Rollen/Immutability |
| T14.02.03 | Normalisierte Kindtabellen implementieren | completed | T14.02.02 | Revision 00019, inventory/automation/security; database/migrations/versions/00019_inventory_processing.py | 189 Datenbanktests; native Rollen/Immutability |
| T14.02.04 | Current-Pointer, Historisierung und Indizes ergänzen | completed | T14.02.03 | Revision 00019, inventory/automation/security; database/migrations/versions/00019_inventory_processing.py | 189 Datenbanktests; native Rollen/Immutability |
| T14.02.05 | Migrationen, Constraints und Datenbankrechte testen | completed | T14.02.04 | Revision 00019, inventory/automation/security; database/migrations/versions/00019_inventory_processing.py | 189 Datenbanktests; native Rollen/Immutability |
| T14.03.01 | Inventory-Worker-Handler registrieren | completed | T14.02.05 | Registry/Worker, Jobtrigger und Backfill; services/inventory/src/cve_inventory/processing.py; main.py | native Claim-/Lease-/Retry-/Recovery-/Backfillfälle |
| T14.03.02 | Jobanlage und Backfill bestehender Submissions implementieren | completed | T14.03.01 | Registry/Worker, Jobtrigger und Backfill; services/inventory/src/cve_inventory/processing.py; main.py | native Claim-/Lease-/Retry-/Recovery-/Backfillfälle |
| T14.03.03 | Konkurrenzsichere Jobübernahme implementieren | completed | T14.03.02 | Registry/Worker, Jobtrigger und Backfill; services/inventory/src/cve_inventory/processing.py; main.py | native Claim-/Lease-/Retry-/Recovery-/Backfillfälle |
| T14.03.04 | Retry, Lease-Verlust und Recovery integrieren | completed | T14.03.03 | Registry/Worker, Jobtrigger und Backfill; services/inventory/src/cve_inventory/processing.py; main.py | native Claim-/Lease-/Retry-/Recovery-/Backfillfälle |
| T14.03.05 | Worker- und Konkurrenztests durchführen | completed | T14.03.04 | Registry/Worker, Jobtrigger und Backfill; services/inventory/src/cve_inventory/processing.py; main.py | native Claim-/Lease-/Retry-/Recovery-/Backfillfälle |
| T14.04.01 | Submission sicher laden und Eingangsvertrag überprüfen | completed | T14.03.05 | Persistierte Metadaten und begrenzte Revalidierung; services/inventory/src/cve_inventory/validation.py | Hash-/Identitäts-/Provenienz-/Zeit-/Schematests |
| T14.04.02 | Inhaltsintegrität und Provenienz prüfen | completed | T14.04.01 | Persistierte Metadaten und begrenzte Revalidierung; services/inventory/src/cve_inventory/validation.py | Hash-/Identitäts-/Provenienz-/Zeit-/Schematests |
| T14.04.03 | Serverreferenz und administrative Isolation prüfen | completed | T14.04.02 | Persistierte Metadaten und begrenzte Revalidierung; services/inventory/src/cve_inventory/validation.py | Hash-/Identitäts-/Provenienz-/Zeit-/Schematests |
| T14.04.04 | Vollständigkeit und Zeitstempel plausibilisieren | completed | T14.04.03 | Persistierte Metadaten und begrenzte Revalidierung; services/inventory/src/cve_inventory/validation.py | Hash-/Identitäts-/Provenienz-/Zeit-/Schematests |
| T14.04.05 | Eingangs-, Provenienz- und Qualitätstests durchführen | completed | T14.04.04 | Persistierte Metadaten und begrenzte Revalidierung; services/inventory/src/cve_inventory/validation.py | Hash-/Identitäts-/Provenienz-/Zeit-/Schematests |
| T14.05.01 | Betriebssysteminformationen normalisieren | completed | T14.04.05 | Normalisierung inventory-1; services/inventory/src/cve_inventory/normalization.py | Debian/RPM/Architektur/Quellpakete/Kernel |
| T14.05.02 | Laufenden Kernel und Hardwaregrundlagen normalisieren | completed | T14.05.01 | Normalisierung inventory-1; services/inventory/src/cve_inventory/normalization.py | Debian/RPM/Architektur/Quellpakete/Kernel |
| T14.05.03 | Debian- und Ubuntu-Pakete normalisieren | completed | T14.05.02 | Normalisierung inventory-1; services/inventory/src/cve_inventory/normalization.py | Debian/RPM/Architektur/Quellpakete/Kernel |
| T14.05.04 | RPM-Pakete normalisieren | completed | T14.05.03 | Normalisierung inventory-1; services/inventory/src/cve_inventory/normalization.py | Debian/RPM/Architektur/Quellpakete/Kernel |
| T14.05.05 | Paketnormalisierung umfassend testen | completed | T14.05.04 | Normalisierung inventory-1; services/inventory/src/cve_inventory/normalization.py | Debian/RPM/Architektur/Quellpakete/Kernel |
| T14.06.01 | Systemdienste normalisieren | completed | T14.05.05 | Dienste, Docker und Qualität; services/inventory/src/cve_inventory/normalization.py; processing.py | Images/Referenzen/Container/Gesamt- und Bereichsstatus |
| T14.06.02 | Docker-Container normalisieren | completed | T14.06.01 | Dienste, Docker und Qualität; services/inventory/src/cve_inventory/normalization.py; processing.py | Images/Referenzen/Container/Gesamt- und Bereichsstatus |
| T14.06.03 | Docker-Images und Referenzen normalisieren | completed | T14.06.02 | Dienste, Docker und Qualität; services/inventory/src/cve_inventory/normalization.py; processing.py | Images/Referenzen/Container/Gesamt- und Bereichsstatus |
| T14.06.04 | Datenqualität und Fehler je Inventarbereich speichern | completed | T14.06.03 | Dienste, Docker und Qualität; services/inventory/src/cve_inventory/normalization.py; processing.py | Images/Referenzen/Container/Gesamt- und Bereichsstatus |
| T14.06.05 | Dienst-, Docker- und Qualitätstests durchführen | completed | T14.06.04 | Dienste, Docker und Qualität; services/inventory/src/cve_inventory/normalization.py; processing.py | Images/Referenzen/Container/Gesamt- und Bereichsstatus |
| T14.07.01 | Snapshotidentität und Unveränderlichkeit implementieren | completed | T14.06.05 | Versiegelung, Fachtransaktion, Current-Pointer; Revision 00019; processing.persist | native Historie/Konkurrenz/Gleichstand/Rollback/Archivierung |
| T14.07.02 | Atomare Snapshot-Persistenz implementieren | completed | T14.07.01 | Versiegelung, Fachtransaktion, Current-Pointer; Revision 00019; processing.persist | native Historie/Konkurrenz/Gleichstand/Rollback/Archivierung |
| T14.07.03 | Aktuellen vollständigen Bestand transaktionssicher auswählen | completed | T14.07.02 | Versiegelung, Fachtransaktion, Current-Pointer; Revision 00019; processing.persist | native Historie/Konkurrenz/Gleichstand/Rollback/Archivierung |
| T14.07.04 | Inventarhistorie und kontrollierte Neuverarbeitung implementieren | completed | T14.07.03 | Versiegelung, Fachtransaktion, Current-Pointer; Revision 00019; processing.persist | native Historie/Konkurrenz/Gleichstand/Rollback/Archivierung |
| T14.07.05 | Snapshot-, Historien- und Auswahltests durchführen | completed | T14.07.04 | Versiegelung, Fachtransaktion, Current-Pointer; Revision 00019; processing.persist | native Historie/Konkurrenz/Gleichstand/Rollback/Archivierung |
| T14.08.01 | Transactional Outbox und Statusübergänge integrieren | completed | T14.07.05 | Outbox, Audit, Performance und Betrieb; processing.py; main.py; scripts/inventory_processor/manage.py | native 10.000 Pakete; Container/DB-Ausfall/SIGKILL; 29 Automationstests |
| T14.08.02 | Übergabevertrag für die Matching Engine implementieren | completed | T14.08.01 | Outbox, Audit, Performance und Betrieb; processing.py; main.py; scripts/inventory_processor/manage.py | native 10.000 Pakete; Container/DB-Ausfall/SIGKILL; 29 Automationstests |
| T14.08.03 | Performance und Datenbankoperationen optimieren | completed | T14.08.02 | Outbox, Audit, Performance und Betrieb; processing.py; main.py; scripts/inventory_processor/manage.py | native 10.000 Pakete; Container/DB-Ausfall/SIGKILL; 29 Automationstests |
| T14.08.04 | Sicherheit, Logging und Betriebsmetriken integrieren | completed | T14.08.03 | Outbox, Audit, Performance und Betrieb; processing.py; main.py; scripts/inventory_processor/manage.py | native 10.000 Pakete; Container/DB-Ausfall/SIGKILL; 29 Automationstests |
| T14.08.05 | Betriebs-, Sicherheits- und Recovery-Tests durchführen | completed | T14.08.04 | Outbox, Audit, Performance und Betrieb; processing.py; main.py; scripts/inventory_processor/manage.py | native 10.000 Pakete; Container/DB-Ausfall/SIGKILL; 29 Automationstests |
| T14.09.01 | Automatisierte Testsuite zusammenführen | completed | T14.08.05 | Integration und Gesamtabnahme; tests/inventory_processor; docs/testing/phase-14-test-matrix.md | Make/CI, vollständige Regressionen und Übergabe |
| T14.09.02 | Vollständigen Ende-zu-Ende-Test durchführen | completed | T14.09.01 | Integration und Gesamtabnahme; tests/inventory_processor; docs/testing/phase-14-test-matrix.md | Make/CI, vollständige Regressionen und Übergabe |
| T14.09.03 | Historien-, Konkurrenz- und Sicherheitsfälle abschließend testen | completed | T14.09.02 | Integration und Gesamtabnahme; tests/inventory_processor; docs/testing/phase-14-test-matrix.md | Make/CI, vollständige Regressionen und Übergabe |
| T14.09.04 | Technische und betriebliche Dokumentation erstellen | completed | T14.09.03 | Integration und Gesamtabnahme; tests/inventory_processor; docs/testing/phase-14-test-matrix.md | Make/CI, vollständige Regressionen und Übergabe |
| T14.09.05 | Phase-14-Gesamtabnahme durchführen | completed | T14.09.04 | Integration und Gesamtabnahme; tests/inventory_processor; docs/testing/phase-14-test-matrix.md | Make/CI, vollständige Regressionen und Übergabe |

Abschluss: 07.11.2026. Keine offenen blockierenden Voraussetzungen innerhalb Phase 14.
Revision 00019 und cve-inventory 0.14.0 sind lokal aktiv; alle sieben eigenen Dienste gesund.
Vorherige Phasenberichte bleiben historisch erhalten. Remote-CI wurde nicht ausgeführt.
