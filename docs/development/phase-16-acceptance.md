# Phase 16 – Gesamtabnahme

Status: **completed**, lokal abgenommen am 08.11.2026. Alle 45 Aufträge, 140 Pflichtprüfungen
und 75 ENR-Invarianten sind im [Status](phase-16-status.md) und in der
[Testmatrix](../testing/phase-16-test-matrix.md) zugeordnet. Keine offenen blockierenden Punkte.

Der geplante Dienst **cve-enricher 0.16.0** verarbeitet die fünf persistierten Quellen mit
Python 3.12 und cve-common 0.7.0. PostgreSQL-Jobs, Leases/Fencing und Transactional Outbox
werden wiederverwendet. Migration **00021** ergänzt quellenbezogene Identitäten, immutable
Enrichment-Revisionen, Provenienz/Assertions und separate EPSS-Datasets. Migration **00022**
vervollständigt die ausdrücklich geforderten Betriebsmetriken ohne erweiterte Runtime-Leserechte.

CVEProject bestimmt den offiziellen Lebenszyklus; NVD, KEV, Ubuntu und OSV ergänzen jeweils
ihren fachlichen Bereich. Explizite Aliase verbinden Advisories und CVEs ohne Verschmelzung.
Entfernte Aliase invalidieren auch alte Kontexte. CVSS 2.0/3.0/3.1/4.0 wird mit cvss 3.6
validiert; Base-/Kontextscore, Versionen und Provider bleiben getrennt. Deterministische
Präferenz und Konflikte sind nachvollziehbar. NVD-Konfigurationslogik und native Ubuntu-/OSV-
Versionssemantik bleiben erhalten. Es findet kein Versionsvergleich mit Serverinventaren statt.

KEV beruht nur auf einem vollständig akzeptierten Katalog. Die unveränderliche Revision
beschreibt dessen Mitgliedschaft; der Current-View liefert altersgeprüftes kev_status und
kev_is_current, damit veraltete Daten keine falsche Negativaussage erzeugen. FIRST EPSS wird
als begrenzte vollständige Gzip-/CSV-Tagesdatei über Envoy mit TLS geladen. Decimal-Werte,
Modell, Datum, Hash, Zeilen, Eindeutigkeit und EOF/CRC werden vor Current-Aktivierung geprüft.
Fehler erhalten den letzten gültigen Stand. Tageskorrekturen und Modellwechsel sind historisch
sichtbar. EPSS erzeugt keine täglichen Enrichment- oder Matching-Massenjobs.

1.131 unterschiedliche relevante Fälle sind nachgewiesen:

| Bereich | Fälle | Nachweis |
|---|---:|---|
| Standard-/Vertrags-/Dienstbasis | 551 | make check |
| Enricher, CVSS, EPSS, Provenienz, PostgreSQL und echter Container | 78 | zusammenhängender 72-Fall-Lauf plus Schlussläufe aller Ergänzungen |
| Vorhandener Phase-15-Importer | 120 | vollständiger Importer-Regressionslauf |
| Datenbankmigrationen, Rechte und bestehender Restore | 189 | vollständiger Datenbanklauf mit Head 00022 |
| Bestehende Jobs, Leases, Fencing und Outbox | 29 | vollständiger Automationslauf |
| Envoy/DNS/SSRF/CONNECT/Namespacefilter | 77 | vollständiger Envoy-Lauf |
| Infrastruktur und bestehende Python-Dienste | 51 | 40 Infrastruktur- und 11 Dienstfälle |
| Inventory Processor einschließlich Recovery | 36 | vollständiger Processor-Lauf |
| Gesamt ohne doppelte Nachläufe | 1.131 | lokale Prüfungen |

Der aktuelle Enricherstand umfasst 22 Normalisierungs-/Vertragsfälle, 27 EPSS-/Transportfälle,
23 native PostgreSQL-/Pipelinefälle und 6 echte Containerfälle. Die 72 ursprünglichen Fälle
liefen zusammenhängend erfolgreich. Zusätzliche Schlussläufe decken Ergebnisvertrag,
vollständige Metriken und vier v4-Base-/Threat-/Environmental-Konstellationen ab. Der tatsächliche
Container wurde nach den letzten fachlichen Änderungen erneut für alle sechs Runtimefälle geprüft;
sein installierter Python-Code stimmt mit der Arbeitskopie überein. XML- und Lognachweise liegen
privat unter .runtime/test-reports/phase-16-*.

Native Nachweise: fünf Quellen vom Importereignis bis zur Enrichment-Revision, offizielle
Rejection mit Historie, unveränderte Rohdaten, Quellen-FKs und Aussagebindung, Mehrfachaliase,
entfernte Zuordnungen, unveränderliche Historien, konkurrierende Identitäten, veraltete Lease
mit vollständigem Rollback, idempotente Wiederholung und expliziter Backfill. Wartende
Identitätsjobs werden koalesziert; laufende Jobs werden bei weiteren Änderungen nicht verloren.
Eine Rückkehr A→B→A verwendet vorhandene Revisionen, sendet aber über monotone Publikationszähler
neue Übergangsereignisse. Lange Advisory-IDs überschreiten keine Job-/Outbox-Grenzen.

EPSS-Nachweise: Grenzen und Präzision, doppelte CVE-IDs, falsche Metadaten/Spalten, fremde
Redirects, defekte Gzip-Dateien, Tageskorrekturen und Wiederveröffentlichung. Ein unvollständiger
Stand wird nie Current. Erfolgreiche EPSS-Aktivierung lässt bestehende Enrichment-Revisionen
unverändert. Backup mit Enrichment/EPSS wurde isoliert restauriert und verglichen.

Container-Recovery: echter PostgreSQL-Stopp, Proxy-Stopp ohne direkten Fallback und SIGKILL
des Workers mit Lease-Recovery; danach erfolgreiche Fortsetzung. Negative Netzwerkprüfungen
trennen eine unerlaubte Quelle mit korrekter Test-CA von einem tatsächlich falschen TLS-Zertifikat.
Ressourcen, non-root/read-only, cap_drop, fehlende Hostports und fehlender Docker-Socket geprüft.
Nach dem zwischenzeitlichen Host-/Docker-Neustart wurden auch die regulären Namespace-Guards
und privaten Nachweise erneuert; alle neun eigenen Dienste sind gesund.

Performance-Baseline des zusammenhängenden Laufs: 1.000 Identitäten mit begrenztem Backfill in
rund **32,53 Sekunden**; 10.000 EPSS-Zeilen mit separater Publikation in rund **3,02 Sekunden**.
Lokale Messwerte, keine Produktions-SLA. Die Betriebsmetriken umfassen Pending/Success/Failure,
Konflikte, gültige CVSS-Abdeckung/Versionen, KEV-/EPSS-Alter, beide Verarbeitungsdauern,
Retryanzahl, Backfillfortschritt, aktive Worker und eigenen gerouteten Outbox-Rückstand.

Ein kollidierender paralleler Legacy-Imagebau wurde durch isolierte temporäre Paketkopien
und einen Buildlock korrigiert. Guardfreigabe wartet auf frische Healthchecks. Die nachfolgenden
Automations- und Importerlaufprüfungen sind vollständig erfolgreich. Frühere fehlgeschlagene
Zwischenläufe werden nicht als bestandene Schlussnachweise gezählt.

Lokale Aktivierung: vollständige private Backups vor beiden Migrationen; Pfade in
phase-16-backup-path.txt und phase-16-observability-backup-path.txt im privaten Berichtordner.
Head **00022_enrichment_observability** aktiv, 16 native Runtime-Logins geprüft, **neun Dienste
gesund**. 69 bestehende Rohdaten-/Fach-/Verwaltungstabellen und die n8n-Datenbank sind gegenüber
dem gespeicherten Vorzustand unverändert. Die normale Datenbank enthält weiterhin keine Benutzer,
Tokens, Server/Gruppen, Inventare/Snapshots, Findings oder Import-/Enrichment-/EPSS-Testdaten.
Mail- und Importer-Bindings sowie die SMTP-Policy sind erhalten. Die vier fremden Nextcloud-
Container bestehen weiterhin mit vor Beginn der Phase angelegten Containerobjekten.

209 geschützte vorhandene Legacy-Dateien stimmen mit dem gespeicherten Schutzmanifest überein.
Die drei beabsichtigten Dependencyänderungen betreffen Runtime-/Dev-Locks und die zusätzliche
CVSS-Bibliothek. Keine Änderung im externen Ansible-Projekt, kein Passwort-/PKI-Reset und keine
manuelle Hostfirewalländerung. Keine Git-Commits oder Pushes. Ruff, Format, striktes Mypy,
Repository-/Schema-/Compose-Validierung und Secretprüfung sind erfolgreich.

Betriebsgrenzen: Initial-/Backfill-/Reconcileaufträge und tägliche EPSS-Zeitplanung sind explizit;
kein ungefragter Vollscan beim Start. Es wurde kein kompletter Internetbestand in die normale
Entwicklungsdatenbank geladen. Quellen-/TLS-E2E verwendet kontrollierte HTTPS-Fixtures.
Remote-GitHub-CI wurde nicht ausgeführt. Matching, Serverbetroffenheit und Findings bleiben
Folgephasen. [Übergabe an Phase 17](phase-16-handover.md).
