# Phase 16 – Aufgabenstatus

Status: completed. Lokal abgenommen am 08.11.2026. Alle 45 Aufträge abgeschlossen.

| Auftrag | Aufgabe | Status | Implementierung/Nachweis |
|---|---|---|---|
| T16.01.01 | Vorhandene CVE-, Datenbank- und Workerarchitektur analysieren | completed | Bestandsanalyse, ADR-0034 und Quellenverträge |
| T16.01.02 | Enrichment-Vertrag und Quellenpriorisierung festlegen | completed | Bestandsanalyse, ADR-0034 und Quellenverträge |
| T16.01.03 | Identitäts-, Alias- und Konfliktregeln definieren | completed | Bestandsanalyse, ADR-0034 und Quellenverträge |
| T16.01.04 | CVSS-, KEV-, EPSS- und Produkt-Evidenzvertrag definieren | completed | Bestandsanalyse, ADR-0034 und Quellenverträge |
| T16.01.05 | Sicherheits-, Revisions- und Matching-Übergabekonzept erstellen | completed | Bestandsanalyse, ADR-0034 und Quellenverträge |
| T16.02.01 | Bestehende Datenbankmodelle und Rollen prüfen | completed | Migrationen 00021/00022; native FKs/Provenienz/Immutable/Minimalrechte |
| T16.02.02 | Identitäten und fachliche Aussagen mit Provenienz modellieren | completed | Migrationen 00021/00022; native FKs/Provenienz/Immutable/Minimalrechte |
| T16.02.03 | CVSS-, KEV- und Produkt-Evidenzmodelle erstellen | completed | Migrationen 00021/00022; native FKs/Provenienz/Immutable/Minimalrechte |
| T16.02.04 | Enrichment-Revisionen und EPSS-Zeitreihen implementieren | completed | Migrationen 00021/00022; native FKs/Provenienz/Immutable/Minimalrechte |
| T16.02.05 | Migrationen, Constraints und Datenbankrechte testen | completed | Migrationen 00021/00022; native FKs/Provenienz/Immutable/Minimalrechte |
| T16.03.01 | `cve-enricher` in die Servicearchitektur integrieren | completed | Registry/Worker, Source-Outbox, begrenzte Kontextjobs und Koaleszierung |
| T16.03.02 | Enrichment-Jobhandler registrieren | completed | Registry/Worker, Source-Outbox, begrenzte Kontextjobs und Koaleszierung |
| T16.03.03 | Änderungsereignisse aus Phase 15 verarbeiten | completed | Registry/Worker, Source-Outbox, begrenzte Kontextjobs und Koaleszierung |
| T16.03.04 | Backfill, Retry und Worker-Recovery implementieren | completed | Registry/Worker, Source-Outbox, begrenzte Kontextjobs und Koaleszierung |
| T16.03.05 | Worker-, Ereignis- und Konkurrenztests durchführen | completed | Registry/Worker, Source-Outbox, begrenzte Kontextjobs und Koaleszierung |
| T16.04.01 | CVE- und Advisory-Identitäten auflösen | completed | normalize.py; explizite Identitäten, Lebenszyklus, Quellen und Konflikte |
| T16.04.02 | Quellenpriorisierung feldbezogen implementieren | completed | normalize.py; explizite Identitäten, Lebenszyklus, Quellen und Konflikte |
| T16.04.03 | CVE-Lebenszyklus, Beschreibungen und Referenzen normalisieren | completed | normalize.py; explizite Identitäten, Lebenszyklus, Quellen und Konflikte |
| T16.04.04 | Alias- und Quellenkonflikte erkennen | completed | normalize.py; explizite Identitäten, Lebenszyklus, Quellen und Konflikte |
| T16.04.05 | Identitäts-, Lebenszyklus- und Quellentests durchführen | completed | normalize.py; explizite Identitäten, Lebenszyklus, Quellen und Konflikte |
| T16.05.01 | CVSS-v2- und CVSS-v3-Parser implementieren | completed | cvss 3.6; versionsgebundene Vektor-/Scoreprüfung und deterministische Auswahl |
| T16.05.02 | CVSS-v4.0-Unterstützung implementieren | completed | cvss 3.6; versionsgebundene Vektor-/Scoreprüfung und deterministische Auswahl |
| T16.05.03 | Score- und Vektorkonsistenz prüfen | completed | cvss 3.6; versionsgebundene Vektor-/Scoreprüfung und deterministische Auswahl |
| T16.05.04 | Bevorzugte CVSS-Bewertung auswählen | completed | cvss 3.6; versionsgebundene Vektor-/Scoreprüfung und deterministische Auswahl |
| T16.05.05 | CVSS-Tests durchführen | completed | cvss 3.6; versionsgebundene Vektor-/Scoreprüfung und deterministische Auswahl |
| T16.06.01 | CISA-KEV-Zugehörigkeit und Herkunft implementieren | completed | Vollständiger KEV-Stand; FIRST-Tages-CSV/Gzip und separate EPSS-Historie |
| T16.06.02 | KEV-Vollständigkeit, Änderungen und Unbekannt-Zustände behandeln | completed | Vollständiger KEV-Stand; FIRST-Tages-CSV/Gzip und separate EPSS-Historie |
| T16.06.03 | FIRST-EPSS-Tagesimport implementieren | completed | Vollständiger KEV-Stand; FIRST-Tages-CSV/Gzip und separate EPSS-Historie |
| T16.06.04 | EPSS-Zeitreihen, Current-Dataset und Reconciliation implementieren | completed | Vollständiger KEV-Stand; FIRST-Tages-CSV/Gzip und separate EPSS-Historie |
| T16.06.05 | KEV- und EPSS-Sicherheitstests durchführen | completed | Vollständiger KEV-Stand; FIRST-Tages-CSV/Gzip und separate EPSS-Historie |
| T16.07.01 | Ubuntu-Sicherheitsstatus und Releasekontext normalisieren | completed | Provenienzgebundene Ubuntu-/OSV-/CNA-/NVD-Evidenz ohne Serververgleich |
| T16.07.02 | Ubuntu-Fixversionen und Backport-Evidenz aufbereiten | completed | Provenienzgebundene Ubuntu-/OSV-/CNA-/NVD-Evidenz ohne Serververgleich |
| T16.07.03 | OSV-Paketidentitäten und Versionsbereiche normalisieren | completed | Provenienzgebundene Ubuntu-/OSV-/CNA-/NVD-Evidenz ohne Serververgleich |
| T16.07.04 | CNA-/NVD-Produkt- und Versionshinweise integrieren | completed | Provenienzgebundene Ubuntu-/OSV-/CNA-/NVD-Evidenz ohne Serververgleich |
| T16.07.05 | Ubuntu-, OSV- und Produkt-Evidenztests durchführen | completed | Provenienzgebundene Ubuntu-/OSV-/CNA-/NVD-Evidenz ohne Serververgleich |
| T16.08.01 | Vollständige Enrichment-Revisionen implementieren | completed | Gefencte Revision/Current/Outbox; Indizes, Recovery, Restore und Performance |
| T16.08.02 | Current-Pointer und idempotente Neuverarbeitung implementieren | completed | Gefencte Revision/Current/Outbox; Indizes, Recovery, Restore und Performance |
| T16.08.03 | Transactional Outbox und Änderungsarten integrieren | completed | Gefencte Revision/Current/Outbox; Indizes, Recovery, Restore und Performance |
| T16.08.04 | Performance, Datenbankindizes und Betriebsmetriken implementieren | completed | Gefencte Revision/Current/Outbox; Indizes, Recovery, Restore und Performance |
| T16.08.05 | Sicherheits-, Konkurrenz- und Recovery-Tests durchführen | completed | Gefencte Revision/Current/Outbox; Indizes, Recovery, Restore und Performance |
| T16.09.01 | Automatisierte Testsuite zusammenführen | completed | Make/CI, Schlussprüfungen, Betriebsdokumentation und Abnahme |
| T16.09.02 | Vollständigen Ende-zu-Ende-Test durchführen | completed | Make/CI, Schlussprüfungen, Betriebsdokumentation und Abnahme |
| T16.09.03 | Historien-, Konflikt-, Konkurrenz- und Sicherheitstests durchführen | completed | Make/CI, Schlussprüfungen, Betriebsdokumentation und Abnahme |
| T16.09.04 | Technische und betriebliche Dokumentation erstellen | completed | Make/CI, Schlussprüfungen, Betriebsdokumentation und Abnahme |
| T16.09.05 | Phase-16-Gesamtabnahme durchführen | completed | Make/CI, Schlussprüfungen, Betriebsdokumentation und Abnahme |

[Abnahme](phase-16-acceptance.md), [Testmatrix](../testing/phase-16-test-matrix.md).

78 aktuelle Enricherfälle und 1.131 unterschiedliche relevante Fälle einschließlich Regression
nachgewiesen. Head 00022, neun eigene Dienste gesund. Keine produktiven Testdatensätze
oder administrativen Änderungen. Einzelheiten in der verlinkten Gesamtabnahme.
