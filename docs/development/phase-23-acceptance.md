# Abnahme Phase 23

Stand: 11.11.2026. **Phase 23 vollständig abgeschlossen: 45 von 45 Aufträgen.** Der ausgeführte Gate ergibt **GO_TO_PHASE_24_REVIEW**, ohne blockierende Befunde oder genehmigte Ausnahmen. Dies erlaubt die anschließende Prüfung in Phase 24; es ist keine Produktionsfreigabe und startet die nächste Phase nicht automatisch.

## Implementierung und aktivierter Stand

API 0.23.0 und additive Migration `00031_hardening_list_projection` sind aktiv. Eindeutige JSON-Verarbeitung, Cookie-/Host-/Portgrenzen, uniforme Containergrenzen, autorisierte Pagination vor Detailprojektion und ausschließlich im API-Sicherheitskontext deaktiviertes JIT sind umgesetzt. Der Auth-Maintenance-Shutdown nach Datenbankausfall ist korrigiert. Objektberechtigungen und fachliche Ergebnissicherheit bleiben erhalten.

Die 13 gesunden Entwicklungsdienste verwenden genau die abschließend gescannten unveränderlichen Artefakte. Die Runtimekorrekturen umfassen SQLite 3.54.1, Expat 2.10.0, Brotli 1.2.1, Kerberos 1.22.3 und Psycopg-C mit System-libpq 18.6. Unbenutzte XML-/XSLT-Module und Bibliotheken sowie alte Kerberos-/RPC-Laufzeitpakete sind aus den betreffenden Infrastrukturimages entfernt. PostgreSQL 18.6 und Node 24.22.2 werden aus festen Quellen gebaut. n8n 2.46.7 behält den bisherigen eingeschränkten Funktionsumfang. [Behebung und Builddetails](../security/phase-23-remediation.md).

## Tatsächliche Prüfungen

| Prüfgruppe | Erfolgreiche Fälle |
|---|---:|
| API und Requestgrenzen | 40 |
| Authentifizierung, MFA und Sessions | 56 |
| RBAC und Serververwaltung | 90 |
| Container, Ingress, Envoy und SMTP | 147 |
| Netzwerk, Proxy und TLS | 113 |
| Datenbank, Rollen und Integrität | 189 |
| Uploads und Inventory Processor | 114 |
| CVE-, Matching-, Finding- und Notification-Pipelines | 688 |
| Automation, Status, Ausfall und Wiederanlauf | 37 |
| Dashboard und Administration einschließlich Browser | 5 |
| Hardening, Last, Restore und Abnahme-Gates | 62 |


Die Gruppen überschneiden sich; ihre Summe ist keine Zahl eindeutiger Tests. Alle konsolidierten Berichte enthalten null Fehler, Fehlschläge und übersprungene Fälle. Frische Image-Regressionsläufe: api: 3, inventory: 36, importer: 10, enricher: 6, matching: 8, findings: 8, notification: 11. Native Labore werden serialisiert. Initiale Fehlerberichte bleiben erhalten; `.sources.json` dokumentiert ausdrücklich ersetzte Ergebnisse anhand Testidentität und SHA256. Die Frontendnachweise enthalten zusätzlich 13 Dashboard-/Administrations-Browserfälle, vier Status-Browserfälle im Gesamtausfalltest und 29 Vitestfälle. Der abschließende Qualitätslauf `make check` besteht mit 646 Standardtests, Ruff, Mypy, Repository-/Schema-/Composevalidierung und Secret-Prüfung bei unveränderter Baseline. Öffentliche JSON-SHA256-Metadaten werden präzise erkannt; ein zusätzlicher Test bestätigt, dass benachbarte Credentials weiterhin abgewiesen werden.

13 Image- und fünf Dependency-SBOMs sowie minimierte Rohreports liegen vor. Die Dependencygraphen umfassen Runtime, Entwicklung, Frontend, n8n und native Buildwerkzeuge. Die abschließenden Scans enthalten **null HIGH-, CRITICAL- oder UNKNOWN-Blocker**. Zusätzlich prüfen native Komponentenproben die tatsächlich eingebundenen Parser-/Kryptobibliotheken, den PostgreSQL-Treiber und die Entfernung ungenutzter Module. Damit werden auch die beim ersten Alpine-Scan erkannten Scannerlücken berücksichtigt. Inventar-/Policyhashes und Frische gehören zum Gate. Die früheren 694 Fundstellen sind als Ausgangsbericht archiviert, keine aktuellen offenen Befunde. [Befundregister](../security/phase-23-image-findings.md).

## Last, Wiederherstellung und Bestandsschutz

Dasselbe synthetische Modell mit 100, 1.000 und 10.000 zusätzlichen Servern/Paketen, je 24 API-Aufrufen und höchstens vier parallelen Aufrufen wurde vor und nach der Optimierung nativ gemessen. Die Baseline hatte 36 API-Fehler. Der finale Lauf hat null Fehler; API-p95 beträgt 237.5 / 215.3 / 200.8 ms gegenüber 4186.2 / 4213.8 / 4106.8 ms. Die gesamte Paket-/Matching-/Findingkette wurde nachgeprüft. Kleine lokale Stichproben sind keine Produktions-SLO. [Messwerte](../performance/performance-results.md).

Authentifizierte AES-256-GCM-Backups mit dateispezifischer HKDF und getrenntem Schlüssel wurden gegen Manipulation, Truncation, falschen Schlüssel und echten ENOSPC getestet. Ein isolierter Restore stellte fünf verschlüsselte Dateien nach Entfernung der Fixture-Klartextquelle wieder her. Vor der Aktivierung wurden beide normalen Datenbanken erneut gesichert. Der zusätzliche physische PostgreSQL-Portabilitätstest bestätigt Anwendungsfingerprints, Unicode-Indizes mit `PG_UNICODE_FAST` und unveränderte Rollen-Credentials. Die normalen Volumes wurden nicht neu initialisiert.

Der finale Livevergleich bestätigt 133 geprüfte geschützte Anwendungstabellen und 57 unveränderte fachliche Pythondateien. 132 Tabellen sind identisch; die zuvor leere Tabelle der Notification-Empfangsbelege enthält zusätzliche, strikt gegen Outbox und Incidents geprüfte interne Statusbelege des Neustarts. Es wurden keine Bestandszeilen gelöscht oder echte Benachrichtigungen erzeugt. Erhalten bleiben außerdem sechs unveränderte Workflowdefinitionen und zwei verschlüsselte n8n-Credentials. Die alten n8n-Daten werden unter den dokumentierten Vendor-Migrationsregeln verglichen: drei zuvor leere Promotiontabellen und der ungenutzte `instanceAi:eval`-Scope mit zwei Grants wurden durch das Upgrade entfernt. Diese begrenzten Metadatenänderungen gelten nicht als byteidentischer Zustand. Die vier fremden Container behalten Identität, Namen und Erstellungszeit. Es gab keine echten Benachrichtigungen oder externen SSH-Zielläufe.

## Reproduktion und Freigabegrenzen

Berichte liegen unter `.runtime/test-reports/phase-23-*`: JUnit, Wiederholungsprovenienz, Lastproben, Recovery, Portabilität, Live-/Artefakt-/Komponentenverifikation, Quellenhashmanifest und `acceptance.json`. `CVE_DOCKER_SUDO=1 make phase-23-acceptance` prüft die tatsächlichen laufenden Artefakte, eingebetteten Komponenten und vollständigen Nachweise. Fehlende, fehlgeschlagene, übersprungene, veraltete oder nicht zu den aktuellen Quellen/Artefakten passende Nachweise sowie offene Scannerbefunde ergeben weiterhin NO_GO.

Offsite- und Schlüsselwiederherstellung, Betriebsverantwortung, externe Überwachung und reale RPO/RTO-/Kapazitätsziele gehören zur Bereitstellungsprüfung in Phase 24. Lokale Hashprovenienz ist keine signierte SLSA-Attestation; die Prüfungen sind keine formale ASVS-Zertifizierung und keine zeitlich unbegrenzte Aussage über Schwachstellenfreiheit.
