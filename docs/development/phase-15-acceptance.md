# Phase 15 – Gesamtabnahme

Status: **completed**, lokal abgenommen am 08.11.2026. Alle 45 Einzelaufträge,
128 Pflichtkriterien und 70 IMP-Invarianten sind in [Status](phase-15-status.md) und
[Testmatrix](../testing/phase-15-test-matrix.md) zugeordnet. Keine offenen blockierenden Punkte.

Implementiert ist cve-importer **0.15.0** auf Python 3.12 und cve-common 0.7.0.
Migration **00020_cve_importer** ergänzt quellengetrennte Rohrecords, unveränderliche
Revisionen, Original-/Inhaltshashes, Provenienz, Aliase, unabhängige Streams, Run-/Quellleases,
persistente Requestbudgets, technische Metriken, Audit und Metadaten-Outbox. Alle fünf
Quellen besitzen Initial-, Änderungs- und kontrollierte Reconcilepfade; für CISA ist das
Änderungsverfahren der vollständige Katalogvergleich. PostgreSQL bleibt die einzige Datenbank.

Die bestehende Worker-/Outbox-/Envoy-Basis wird verwendet. HTTPS erfordert den gebundenen
Envoy-Tunnel, geschlossene Hosts/Pfade, TLS-Prüfung und kontrollierte Redirects. Parser und
ZIP-/CSV-Verarbeitung laufen begrenzt und isoliert; Downloads, Entpacken, Felder, Dateien,
Batches und Scratchbestand haben feste Grenzen. Für große Archive und Änderungsindizes
wird einmal gelesen, mit Rückdruck nach jedem persistierten Batch. Ein erfolgreicher
Quellcursor folgt erst nach allen erforderlichen Seiten, Fenstern und Teilströmen.

1.053 unterschiedliche relevante Fälle sind nachgewiesen:

| Bereich | Fälle | Nachweis |
|---|---:|---|
| Standard-/Vertrags-/Dienstbasis | 551 | make check |
| Importer: Parser, HTTP, native DB, fünf Adapter, echter Container, Recovery | 120 | 111 zusammenhängend; gezielte aktuelle Schlussläufe, siehe unten |
| Bestehende Datenbankmigrationen, native Rechte, Persistenz und Restore | 189 | make db-test |
| Bestehende Jobs, Leases, Fencing und Outbox | 29 | make automation-integration |
| Envoy/DNS/SSRF/CONNECT/Namespacefilter | 77 | make envoy-test |
| Infrastruktur und bestehende Python-Dienstintegration | 51 | 40 infra-test, 11 services-integration |
| Inventory Processor einschließlich Ausfälle/Integrität | 36 | make inventory-processor-integration |
| Gesamt ohne doppelte Nachläufe | 1.053 | lokale Prüfungen |

Importer-Schlussstand: 81 Parser-/HTTP-/Konfigurationsfälle, 8 native Datenbank-/Operatorfälle,
21 Pipeline-/Revisions-/Recovery-/Konkurrenz-/Restorefälle und 10 tatsächliche Containerfälle.
Der zusammenhängende 111-Fall-Lauf wurde ergänzt durch die native Quellrennenprüfung,
die Operator-Rechteinspektion, explizite Budgetfortsetzung am Checkpoint, zusätzliche Archiv-/CSV-Negativfälle und erneute Prüfung
aller geänderten Teile. Mehrzeilige private JSON-Konfiguration wird ausdrücklich im echten
Container geprüft; sie wird über einen geeigneten privaten Dateileser eingelesen.
Die Rechteinspektion benötigt keine erweiterten Fachschema-Rechte und liest Katalog-OIDs.

Nachgewiesen sind Initialimport und identische Wiederholung aller fünf Quellen,
REJECTED/Withdrawn, Alias-/Quellenisolation, vollständige NVD-Pagination,
gültige Records bei Teilfehlern ohne Erfolgscursor, KEV-Entfernung nur bei Vollständigkeit,
Rückgangschutz, OSV-Einzelrecordprovenienz, historische Korrektur versus älterer inkrementeller
Revision, native Unveränderlichkeit und konkurrierende Quellenaufträge.

Recovery: Abbruch nach einem committed Batch und Wiederanlauf an dessen Nachfolger;
veraltete Lease mit zurückgerollter Fachtransaktion; echte PostgreSQL-/Proxy-Unterbrechung;
SIGKILL des Importer-Prozesses mit erneutem Binding und Lease-Recovery; erfolgreiche
Fortsetzung ohne Doppelrevision. Vollständiges Backup mit Quellenrevisionen wurde in eine
isolierte Instanz zurückgespielt und Inhalte/Kataloge/Rechte verglichen. Dauerhaft fehlgeschlagene
Jobs erzeugen nachvollziehbare Failure-Metadaten und erlauben einen expliziten Folgeauftrag.

Performance-Baseline: 1.000 vollständige OSV-Testrecords wurden mit realem PostgreSQL,
set-orientierter Persistenz und begrenztem Parser in rund **3,08 Sekunden** verarbeitet
(JUnit-Fallzeit im Gesamtlauf). Dies ist eine lokale Testmessung und keine SLA für vollständige
Internetbestände. Worker, Datenbankpool, Parser, Download und Containerressourcen sind begrenzt.

Lokale Aktivierung: Vor Migration wurde ein vollständiges privates Backup erstellt
(Pfad in .runtime/test-reports/phase-15-backup-path.txt). Head 00020 ist aktiv;
alle **acht** eigenen Dienste sind gesund, 16 native Runtime-Logins geprüft.
Die installierten 50 Python-/JSON-Dateien stimmen mit der Arbeitskopie überein.
51 geschützte administrative/Fachtabellen und die n8n-Datenbank sind unverändert.
Mail-Relay-Binding und SMTP-Policy sind erhalten; die vier fremden Nextcloudcontainer
behalten ihre IDs. Die reguläre Datenbank enthält weiterhin keine Benutzer, Tokens,
Server/Gruppen, Inventare/Snapshots, Findings oder Quellenimportläufe/-records.

212 geschützte vorhandene Dateien, darunter die ersten 19 Migrationen, ältere Dienste,
gemeinsame Basis, Inventar-/Sicherheitsverträge, Locks und Secret-Baseline sind hashgleich.
Keine Änderungen im externen Ansible-Projekt, keine manuelle Hostfirewalländerung,
keine normalen Passwort-/PKI-Resets, kein Commit/Push. Ruff, Format, Mypy,
Repository-/Schema-/Compose-Validierung und Secretprüfung sind erfolgreich.

Bewusste Betriebsgrenzen: OSV-Ökosysteme müssen explizit gewählt werden; Initialimporte,
Reconcile und spätere Zeitplanung werden ausdrücklich beauftragt. Es wurde kein kompletter
Internetbestand in die normale Entwicklungsdatenbank geladen. Quellen-/TLS-E2E verwendet
kontrollierte schema-konforme HTTPS-Fixtures. Remote-GitHub-CI wurde nicht ausgeführt.
CVEProject-Tageswechsel erfordern Reconcile; ein Retry-After außerhalb des Wartebudgets
führt zu partial und verlangt Abwarten der Quellfrist vor einem expliziten Folgeauftrag.
Die bekannte doppelte scoreType-Definition dreier unveränderter Upstream-CVSS-Schemas
ist ausschließlich pfad- und hashgebunden im Repositoryvalidator zugelassen.

Private Evidenz: .runtime/test-reports/phase-15-*. Die finale Quellen-/Betriebsdokumentation,
[ADR-0033](../architecture/decisions/ADR-0033-source-import-phase15.md) und
[Übergabe](phase-15-handover.md) halten Schnittstellen und Einschränkungen fest.
Phase 16 wurde nicht begonnen.

Große Erstimporte besitzen einen dokumentierten expliziten `resume --run-id`-Pfad:
Der bestehende Job-Replay erneuert das begrenzte Zeitbudget und verwendet denselben Run
mit unverändertem Fenster/Checkpoint. Ein nativer Test bestätigt Fortsetzung nach zwei
bereits committed Records bis zum vollständigen Fünf-Record-Ergebnis, inklusive Ablehnung
einer doppelten Wiederaufnahme. Keine automatische unbegrenzte Retryschleife.
