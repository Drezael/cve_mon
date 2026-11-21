# Phase 14 – Gesamtabnahme

Status: **completed**, lokal abgenommen am 07.11.2026. Alle 45 Einzelaufträge und die
128 Pflichtkriterien sind nachgewiesen. Keine offenen blockierenden Probleme in Phase 14.

Der vorgesehene Dienst cve-inventory 0.14.0 verarbeitet beide Annahmewege über die vorhandene
PostgreSQL-Jobinfrastruktur. Migration 00019 ergänzt versiegelte Snapshots und Kinddaten,
Zuordnungsintegrität, Historie, Current-Pointer, Backfill, Audit/Outbox und Metriken. Die
Originalschemata 1.0/1.1 und bestehende Annahme-Receipts bleiben unverändert. Das externe
Ansible-Repository benötigt keine Änderung.

934 unterschiedliche relevante Testfälle wurden nachgewiesen:

| Bereich | Fälle | Schlussnachweis |
|---|---:|---|
| Standardtests einschließlich 42 neuer Normalisierungs-/Vertragsfälle | 551 | make check; Ruff, Format, Mypy, Validator und Secret-Prüfung ebenfalls erfolgreich |
| Processor/PostgreSQL/API/Container | 36 | Gesamtlauf mit 32 Fällen; gezielte Nachprüfung von Idempotenz, Legacy-Kollisionen, Binding-Trigger, Metriken und Current-View; alle aktuellen Fälle nachgewiesen |
| Datenbankmigrationen, Rechte und bestehende Backup-/Restoretests | 189 | vollständiger Datenbanklauf |
| Phase-7-Jobs, Outbox, Leases, Fencing und Ausfälle | 29 | vollständiger Automationslauf |
| Infrastruktur und Python-Dienstintegration | 51 | 40 Infrastruktur- und 11 Dienstfälle |
| Bestehende Upload-/Ansible-Submitintegration | 78 | vollständiger Lauf plus gezielter 23-Fall-Nachlauf der angepassten Rechte-/Jobannahmen |
| Summe ohne doppelt gezählte Nachläufe | 934 | lokale Abnahme |

Der vollständige Uploadlauf fand eine überholte Vor-Phase-14-Annahme: inventory_processor
benötigt jetzt ausdrücklich Rohinventar-Leserechte. Der angepasste Nachlauf prüft weiterhin
verbotene Verwaltungs-/Credentialzugriffe und bestätigt die neue ausschließlich technische
Leseberechtigung. Die frühere Null-Job-Annahme wurde durch eine Prüfung des tatsächlich
referenzierten Jobs mit einzigem Argument submission_id ersetzt.

Die Integritätsnachprüfung ergänzt kontrollierte Ablehnung bereits vorhandener Legacy-IDs,
einen nativen Binding-Trigger und den Vorrang eines verifizierten Pointers vor Legacy-Views.
Erwartete Datenbankablehnungen werden über zurückgerollte Savepoints geprüft. Technischer
Replay bleibt auditiert und erzeugt keine unkontrollierten Snapshots. Der Wheel-Bau erfolgt
in frischen temporären Quellverzeichnissen; die Integration vergleicht den tatsächlich im
Image installierten Verarbeitungs-, Validierungs- und Normalisierungscode mit der Arbeitskopie.

Performance-Baseline: 10.000 Pakete plus je 600 Container und Images wurden mit dem
PostgreSQL-Worker in rund **5,06 Sekunden** verarbeitet. Gemessen auf dem lokalen Host mit
realem isolierten PostgreSQL und begrenztem Normalisierungsprozess; keine Produktions-SLA.
Das tatsächliche Dockerimage wird separat mit Ressourcen-, Netzwerk- und Ausfalltests geprüft.
Alle Versionen, Epoch/Release, Architekturen, Referenzen und Objektanzahlen blieben erhalten.

Reale Ausfallnachweise: verlorene Lease mit zurückgerollter Fachtransaktion; Retry bis zur
Erschöpfung und anschließender expliziter Replay; PostgreSQL-Stopp/Neustart; SIGKILL und
Containerneustart; persistenter Snapshot und kein Duplikat. Zusätzlich wurde ein Backup mit
verarbeiteten Snapshots, Provenienz und Kinddaten isoliert wiederhergestellt und vollständig
auf Tabelleninhalte, Kataloge, Eigentümer und Rechte verglichen.

Lokale Aktivierung: Vor Migration wurde ein privates vollständiges Backup erstellt.
Revision **00019_inventory_processing** ist aktiv, cve-inventory läuft gesund. Alle sieben
eigenen Dienste sind gesund. Native Runtime-Logins und Metadatenprüfungen sind erfolgreich;
Snapshotprüfung meldet 0 Inkonsistenzen. Es wurden keine fachlichen Live-Testdaten angelegt:
Benutzer, technische Clients/Tokens, Server/Gruppen, Submissions und Snapshots jeweils 0.
Administrative Tabellen sind vor/nach Aktivierung hashgleich. Alle vier fremden
Nextcloudcontainer behalten ihre ursprünglichen IDs. Dispatcherziele bleiben geschlossen.

Unverändert: erste 18 Migrationen, Eingangsverträge, API 0.11.1, cve-common/Dispatcher 0.7.0,
Lockdateien und Secret-Baseline. 202 geschützte CVE-Dateien und alle 197 geprüften vorhandenen
Ansible-Dateien sind hashgleich. Keine Änderungen an Hostfirewall, normaler PKI oder
Zielservern; keine Git-Commits oder Pushes. Remote-GitHub-CI wurde nicht ausgeführt.
Eine neue fachliche Normalisierung bereits erfolgreicher Snapshots und Retention bleiben
ausdrücklich gesonderte spätere Aufgaben; normaler technischer Retry/Replay ist implementiert.

Private Testnachweise liegen unter .runtime/test-reports/phase-14-*. Die aktuelle Dateiliste
und SHA-256-Nachweise stehen im [Manifest](phase-14-files.json).
[Einzelaufträge](phase-14-status.md), [Testmatrix](../testing/phase-14-test-matrix.md),
[Architektur](../architecture/inventory-processor.md), [Betrieb](../operations/inventory-processor.md),
[Übergabe](phase-14-handover.md).

## Einzelabnahme der Pflichtkriterien

| Nr. | Kriterium | Ergebnis / Nachweis |
|---|---|---|
| 1 | Vorhandene Architektur berücksichtigt. | erfüllt: Bestandsanalyse, ADR-0032, vorhandene cve-common-Registry/Worker/Outbox und geschlossene Dienste |
| 2 | Bestehender Dienst `cve-inventory` wiederverwendet. | erfüllt: Bestandsanalyse, ADR-0032, vorhandene cve-common-Registry/Worker/Outbox und geschlossene Dienste |
| 3 | Keine neue unabhängige Inventarverarbeitung. | erfüllt: Bestandsanalyse, ADR-0032, vorhandene cve-common-Registry/Worker/Outbox und geschlossene Dienste |
| 4 | PostgreSQL als einzige Datenbank. | erfüllt: Bestandsanalyse, ADR-0032, vorhandene cve-common-Registry/Worker/Outbox und geschlossene Dienste |
| 5 | Keine zusätzliche Queue. | erfüllt: Bestandsanalyse, ADR-0032, vorhandene cve-common-Registry/Worker/Outbox und geschlossene Dienste |
| 6 | Keine Redis-Abhängigkeit. | erfüllt: Bestandsanalyse, ADR-0032, vorhandene cve-common-Registry/Worker/Outbox und geschlossene Dienste |
| 7 | Keine zusätzliche n8n-Abhängigkeit. | erfüllt: Bestandsanalyse, ADR-0032, vorhandene cve-common-Registry/Worker/Outbox und geschlossene Dienste |
| 8 | Vorhandene Workerinfrastruktur verwendet. | erfüllt: Bestandsanalyse, ADR-0032, vorhandene cve-common-Registry/Worker/Outbox und geschlossene Dienste |
| 9 | Vorhandene Transactional Outbox verwendet. | erfüllt: Bestandsanalyse, ADR-0032, vorhandene cve-common-Registry/Worker/Outbox und geschlossene Dienste |
| 10 | Unterstützte Submissions korrekt übernommen. | erfüllt: nativer Claim-/Backfill-/Idempotenznachweis |
| 11 | Bereits angenommene Submissions können nachverarbeitet werden. | erfüllt: nativer Claim-/Backfill-/Idempotenznachweis |
| 12 | Keine doppelte Jobanlage bei Backfill. | erfüllt: nativer Claim-/Backfill-/Idempotenznachweis |
| 13 | Submission-ID eindeutig. | erfüllt: nativer Claim-/Backfill-/Idempotenznachweis |
| 14 | Server-UUID korrekt. | erfüllt: geschlossene 1.0/1.1-Verträge, Hash-/Identitäts-/Provenienzprüfung und native Annahme |
| 15 | Provenienz übernommen. | erfüllt: geschlossene 1.0/1.1-Verträge, Hash-/Identitäts-/Provenienzprüfung und native Annahme |
| 16 | Schema-Version geprüft. | erfüllt: geschlossene 1.0/1.1-Verträge, Hash-/Identitäts-/Provenienzprüfung und native Annahme |
| 17 | Unbekannte Schema-Version abgelehnt. | erfüllt: geschlossene 1.0/1.1-Verträge, Hash-/Identitäts-/Provenienzprüfung und native Annahme |
| 18 | JSON-Vertrag geprüft. | erfüllt: geschlossene 1.0/1.1-Verträge, Hash-/Identitäts-/Provenienzprüfung und native Annahme |
| 19 | Keine automatische Serverregistrierung. | erfüllt: geschlossene 1.0/1.1-Verträge, Hash-/Identitäts-/Provenienzprüfung und native Annahme |
| 20 | Keine automatische Serverreaktivierung. | erfüllt: native Rechte-/SQL-Ablehnungen und unveränderte administrative Live-Fingerprints |
| 21 | Keine administrative Serveränderung. | erfüllt: native Rechte-/SQL-Ablehnungen und unveränderte administrative Live-Fingerprints |
| 22 | Keine Gruppenänderung. | erfüllt: native Rechte-/SQL-Ablehnungen und unveränderte administrative Live-Fingerprints |
| 23 | Keine Primärgruppenänderung. | erfüllt: native Rechte-/SQL-Ablehnungen und unveränderte administrative Live-Fingerprints |
| 24 | Keine Sortieränderung. | erfüllt: native Rechte-/SQL-Ablehnungen und unveränderte administrative Live-Fingerprints |
| 25 | Keine ACL-Änderung. | erfüllt: native Rechte-/SQL-Ablehnungen und unveränderte administrative Live-Fingerprints |
| 26 | Datenbankrechte tatsächlich getestet. | erfüllt: native Rechte-/SQL-Ablehnungen und unveränderte administrative Live-Fingerprints |
| 27 | Betriebssystem normalisiert. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 28 | Distribution erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 29 | Distributionsversion erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 30 | Architektur erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 31 | Kernelinformationen normalisiert. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 32 | Laufender Kernel separat erkennbar. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 33 | Installierte Kernelpakete erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 34 | Paketmanager erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 35 | Paketnamen korrekt. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 36 | Vollständige Paketversionen erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 37 | Debian-Epoch erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 38 | Debian-Revision erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 39 | Ubuntu-Revision erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 40 | RPM-Epoch erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 41 | RPM-Version erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 42 | RPM-Release erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 43 | Paketarchitektur erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 44 | Mehrfachversionen erhalten. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 45 | Keine naive SemVer-Konvertierung. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 46 | Keine fehlerhafte Versionsverkürzung. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 47 | Keine unkontrollierte CPE-Zuordnung. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 48 | Keine erfundenen Package URLs. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 49 | Keine CVE-Bewertung durchgeführt. | erfüllt: Normalisierungstests, Originaldatenerhalt und echte Paket-Bulkpersistenz |
| 50 | Dienste normalisiert. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 51 | Dienstzustände erhalten. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 52 | Kein Live-Servicecheck. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 53 | Container normalisiert. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 54 | Containerstatus erhalten. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 55 | Container-Image-Referenz erhalten. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 56 | Images normalisiert. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 57 | Image-IDs erhalten. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 58 | Image-Digests erhalten, soweit verfügbar. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 59 | Mehrere Image-Tags unterstützt. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 60 | Keine Docker-API verwendet. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 61 | Kein Docker-Socket. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 62 | Keine Registry-Kommunikation. | erfüllt: Dienst-/Container-/Imageprüfung, strukturierte Referenzen, Bulkbestand und isoliertes Image |
| 63 | Vollständigkeitsstatus korrekt. | erfüllt: Qualitäts-/Zeit-/Partial-/Failed-/Leere-Listen-Prüfungen |
| 64 | Teilweise Inventare korrekt. | erfüllt: Qualitäts-/Zeit-/Partial-/Failed-/Leere-Listen-Prüfungen |
| 65 | Fehlgeschlagene Erfassungsbereiche nachvollziehbar. | erfüllt: Qualitäts-/Zeit-/Partial-/Failed-/Leere-Listen-Prüfungen |
| 66 | Leere und fehlende Daten unterschieden. | erfüllt: Qualitäts-/Zeit-/Partial-/Failed-/Leere-Listen-Prüfungen |
| 67 | Zukunftszeitstempel behandelt. | erfüllt: Qualitäts-/Zeit-/Partial-/Failed-/Leere-Listen-Prüfungen |
| 68 | Erfassungszeitpunkt erhalten. | erfüllt: Qualitäts-/Zeit-/Partial-/Failed-/Leere-Listen-Prüfungen |
| 69 | Annahmezeitpunkt erhalten. | erfüllt: Qualitäts-/Zeit-/Partial-/Failed-/Leere-Listen-Prüfungen |
| 70 | Verarbeitungszeitpunkt erhalten. | erfüllt: Qualitäts-/Zeit-/Partial-/Failed-/Leere-Listen-Prüfungen |
| 71 | Unveränderlicher Snapshot erzeugt. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 72 | Snapshot-ID eindeutig. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 73 | Submission-Referenz korrekt. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 74 | Server-Referenz korrekt. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 75 | Normalisierungsversion gespeichert. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 76 | Originaler Payload-Hash erhalten. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 77 | Keine historischen Snapshots überschrieben. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 78 | Kinddatensätze transaktional gespeichert. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 79 | Keine unvollständigen erfolgreichen Snapshot-Commits. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 80 | Doppelte Verarbeitung erzeugt keine unkontrollierten Duplikate. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 81 | Current-Pointer korrekt. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 82 | Neuere vollständige Inventare werden berücksichtigt. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 83 | Ältere verspätete Inventare verdrängen keine neueren vollständigen. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 84 | Teilweise Inventare verdrängen keine vollständigen. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 85 | Fehlgeschlagene Inventare verdrängen keine vollständigen. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 86 | Gleichzeitige Worker verletzen keine Current-Pointer-Regeln. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 87 | Archivierte Server korrekt behandelt. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 88 | Keine automatische Historienlöschung. | erfüllt: native Versiegelung, Binding, Rollback, Historie und konkurrierende Current-Auswahl |
| 89 | Submissionstatus korrekt. | erfüllt: getrennte Zustände, generische Phase-7-Ausfälle und echte Processor-/Container-Recovery |
| 90 | Jobstatus korrekt. | erfüllt: getrennte Zustände, generische Phase-7-Ausfälle und echte Processor-/Container-Recovery |
| 91 | Job- und Submissionstatus nicht verwechselt. | erfüllt: getrennte Zustände, generische Phase-7-Ausfälle und echte Processor-/Container-Recovery |
| 92 | Lease-Verhalten korrekt. | erfüllt: getrennte Zustände, generische Phase-7-Ausfälle und echte Processor-/Container-Recovery |
| 93 | Heartbeat berücksichtigt. | erfüllt: getrennte Zustände, generische Phase-7-Ausfälle und echte Processor-/Container-Recovery |
| 94 | Retry-Verhalten korrekt. | erfüllt: getrennte Zustände, generische Phase-7-Ausfälle und echte Processor-/Container-Recovery |
| 95 | Permanente Fehler werden nicht endlos wiederholt. | erfüllt: getrennte Zustände, generische Phase-7-Ausfälle und echte Processor-/Container-Recovery |
| 96 | Workerabsturz ist wiederaufnehmbar. | erfüllt: getrennte Zustände, generische Phase-7-Ausfälle und echte Processor-/Container-Recovery |
| 97 | PostgreSQL-Ausfall ist beherrschbar. | erfüllt: getrennte Zustände, generische Phase-7-Ausfälle und echte Processor-/Container-Recovery |
| 98 | Transaktionsrollback funktioniert. | erfüllt: getrennte Zustände, generische Phase-7-Ausfälle und echte Processor-/Container-Recovery |
| 99 | Keine doppelten Snapshots nach Recovery. | erfüllt: getrennte Zustände, generische Phase-7-Ausfälle und echte Processor-/Container-Recovery |
| 100 | Outbox-Ereignisse vorhanden. | erfüllt: atomare Outbox/Audit, unveränderte Verwaltung und reale Container-/Netzwerkisolation |
| 101 | Kein Matching vorzeitig implementiert. | erfüllt: atomare Outbox/Audit, unveränderte Verwaltung und reale Container-/Netzwerkisolation |
| 102 | Kein Finding Management vorzeitig implementiert. | erfüllt: atomare Outbox/Audit, unveränderte Verwaltung und reale Container-/Netzwerkisolation |
| 103 | Keine direkte SSH-Verbindung. | erfüllt: atomare Outbox/Audit, unveränderte Verwaltung und reale Container-/Netzwerkisolation |
| 104 | Keine Ansible-Ausführung. | erfüllt: atomare Outbox/Audit, unveränderte Verwaltung und reale Container-/Netzwerkisolation |
| 105 | Keine externe HTTP-Verbindung. | erfüllt: atomare Outbox/Audit, unveränderte Verwaltung und reale Container-/Netzwerkisolation |
| 106 | Keine unnötigen öffentlichen Ports. | erfüllt: atomare Outbox/Audit, unveränderte Verwaltung und reale Container-/Netzwerkisolation |
| 107 | Keine unnötigen Containerprivilegien. | erfüllt: atomare Outbox/Audit, unveränderte Verwaltung und reale Container-/Netzwerkisolation |
| 108 | Keine Secrets in Logs. | erfüllt: atomare Outbox/Audit, unveränderte Verwaltung und reale Container-/Netzwerkisolation |
| 109 | Worker-Health funktioniert. | erfüllt: reale Health-/DB-Ausfalltests, Metriken, Batch-/Indexprüfung und dokumentierte Performance |
| 110 | Betriebsmetriken vorhanden. | erfüllt: reale Health-/DB-Ausfalltests, Metriken, Batch-/Indexprüfung und dokumentierte Performance |
| 111 | Batch-Inserts verwendet. | erfüllt: reale Health-/DB-Ausfalltests, Metriken, Batch-/Indexprüfung und dokumentierte Performance |
| 112 | Große Paketlisten funktionieren. | erfüllt: reale Health-/DB-Ausfalltests, Metriken, Batch-/Indexprüfung und dokumentierte Performance |
| 113 | Begrenzte Workerparallelität. | erfüllt: reale Health-/DB-Ausfalltests, Metriken, Batch-/Indexprüfung und dokumentierte Performance |
| 114 | Geeignete Datenbankindizes. | erfüllt: reale Health-/DB-Ausfalltests, Metriken, Batch-/Indexprüfung und dokumentierte Performance |
| 115 | Unit-Tests erfolgreich. | erfüllt: erfolgreiche lokale Qualitäts-, Integrations-, Sicherheits-, Konkurrenz-, Recovery- und E2E-Nachweise |
| 116 | PostgreSQL-Integrationstests erfolgreich. | erfüllt: erfolgreiche lokale Qualitäts-, Integrations-, Sicherheits-, Konkurrenz-, Recovery- und E2E-Nachweise |
| 117 | Worker-Konkurrenztests erfolgreich. | erfüllt: erfolgreiche lokale Qualitäts-, Integrations-, Sicherheits-, Konkurrenz-, Recovery- und E2E-Nachweise |
| 118 | Snapshot-Integritätstests erfolgreich. | erfüllt: erfolgreiche lokale Qualitäts-, Integrations-, Sicherheits-, Konkurrenz-, Recovery- und E2E-Nachweise |
| 119 | Historientests erfolgreich. | erfüllt: erfolgreiche lokale Qualitäts-, Integrations-, Sicherheits-, Konkurrenz-, Recovery- und E2E-Nachweise |
| 120 | Current-Pointer-Tests erfolgreich. | erfüllt: erfolgreiche lokale Qualitäts-, Integrations-, Sicherheits-, Konkurrenz-, Recovery- und E2E-Nachweise |
| 121 | Sicherheitstests erfolgreich. | erfüllt: erfolgreiche lokale Qualitäts-, Integrations-, Sicherheits-, Konkurrenz-, Recovery- und E2E-Nachweise |
| 122 | Ausfall- und Recovery-Tests erfolgreich. | erfüllt: erfolgreiche lokale Qualitäts-, Integrations-, Sicherheits-, Konkurrenz-, Recovery- und E2E-Nachweise |
| 123 | Performance-Baseline dokumentiert. | erfüllt: erfolgreiche lokale Qualitäts-, Integrations-, Sicherheits-, Konkurrenz-, Recovery- und E2E-Nachweise |
| 124 | Ende-zu-Ende-Test erfolgreich. | erfüllt: erfolgreiche lokale Qualitäts-, Integrations-, Sicherheits-, Konkurrenz-, Recovery- und E2E-Nachweise |
| 125 | Dokumentation vollständig. | erfüllt: vollständige Dokumentation und begrenzte Übergabe an Phase 15/17; kein Matching/Finding vorgezogen |
| 126 | Übergabe an Phase 15 vorbereitet. | erfüllt: vollständige Dokumentation und begrenzte Übergabe an Phase 15/17; kein Matching/Finding vorgezogen |
| 127 | Übergabe an Phase 17 vorbereitet. | erfüllt: vollständige Dokumentation und begrenzte Übergabe an Phase 15/17; kein Matching/Finding vorgezogen |
| 128 | Keine unzulässigen Architekturänderungen. | erfüllt: vollständige Dokumentation und begrenzte Übergabe an Phase 15/17; kein Matching/Finding vorgezogen |
