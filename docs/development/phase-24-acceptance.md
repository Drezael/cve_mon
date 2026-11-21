# Phase 24 – Abnahme und Nachweismatrix

Die folgende Matrix erfasst alle 186 Kriterien aus Kapitel 58 und alle 105
DEP-Invarianten. Sie ist eine Zuordnung und keine pauschale Bestanden-Erklärung.
Der maschinenprüfbare Abschluss steht in `.runtime/test-reports/phase-24-acceptance.json`.
Ohne erfolgreichen vollständigen Native-Lauf bleiben technische Kriterien offen.
Ohne saubere reale Git-Releaseidentität und ausdrückliche Betreiberfreigabe ist
Produktion NO-GO. Testdaten, synthetische Signaturen in Unit-Tests und ein
technischer Smoke sind keine Produktivfreigabe.

## Evidenztypen

- **N**: frischer Phase-24-Lauf: `phase-24-native.xml`, `phase-24-native-stage.json`;
  neue Installation mit 13 gepinnten Images, HTTPS und Idempotenz.
- **B**: frische fachliche Kette: `phase-24-business-chain.json`,
  `phase-24-business-administration.json` und Native-JUnit. Ansible-/mTLS-
  Submission und Dashboard-/MFA-Upload, echte kontrollierte Quellhandler bis
  Finding und native n8n/Postfix/Envoy-Zustellung; keine externen Empfänger.
  Deterministische Source-/Matching-/Findinghandler werden bei gestoppten
  konkurrierenden Prozessoren ausgeführt. Die native Workerabdeckung stammt
  zusätzlich aus **P**; die beiden Nachweise dürfen nicht verwechselt werden.
- **R**: frisches `phase-24-full-recovery.json`, isolierter DB-Restore mit
  Daten-/Katalog-/Rollenvergleich, 13 wiederhergestellte Dienste, identische
  n8n-Keys und tatsächlich entschlüsselte zwei Credentials.
- **O**: `phase-24-outage-exercise.json`, `phase-24-offline-images.json`;
  API-/DB-Ausfall und kontrollierter Wiederanlauf, Offlineexport/-import aller Images.
- **U**: `phase-24-unit.xml` und `phase-24-check.log`; Signaturbindung,
  Manipulation/Lock/Journal/Pfadschutz, Migrationsplan und n8n-DDL-Negativtests.
- **P**: eindeutig als übernommen gekennzeichnete Phase-23-Nachweise für
  **dieselben** Image- und Frontendartefakte: `phase-23-test-summary.json`,
  Security-JUnitgruppen, Image-/Dependencygates, SBOMs, Performance und Resilienz.
  Gruppen überlappen; Zahlen dürfen nicht als einzigartige Tests addiert werden.
  Phase 24 ändert Operatorcode, keinen fachlichen Imagesource. Neue Operator-
  Regressionen werden durch N/B/R/O/U geprüft. Geänderte Images/Scannerinputs
  oder veraltete Scans entwerten diese Übernahme.
- **D**: [Deployment](../deployment/release-and-recovery.md),
  [Betrieb](../operations/platform-handbook.md),
  [Bedienung](../dashboard/platform-manual.md),
  Plan (nur lokal archiviert) und [Übergabe](phase-24-handover.md).
- **F**: formale Freigabe: sauberer tatsächlicher Git-Commit, aktueller vollständiger
  Releasebezug, Betreiberentscheidungen und gegebenenfalls konkrete signierte
  Produktivgenehmigung. Solange diese fehlen, keine formale Gesamtfreigabe.

## Gates

G24.0 prüft die Phase-23-Voraussetzungen. G24.1 bindet Artefakte, SBOM und reale
Gitidentität. G24.2 prüft Konfiguration/Secrets/PKI. G24.3 prüft Migrationen und
Rollen. G24.4 prüft vollständiges Backup/Restore. G24.5 prüft Staginginstallation.
G24.6 prüft fachliche E2E. G24.7 prüft Security/Performance/Resilienz.
G24.8 benötigt ausdrückliche Produktivfreigabe; G24.9 benötigt den tatsächlichen
Postdeployment-/Betriebsnachweis im freigegebenen Ziel. Stagingübungen belegen
keinen nicht durchgeführten Produktionsstart.

## 186 Abschlusskriterien

| Nr. | Kriterium | Nachweise |
|---|---|---|
| 1 | Vollständige Servicearchitektur vorhanden. | N, P |
| 2 | Docker-Compose-Konfiguration gültig. | N, P |
| 3 | Keine unnötigen öffentlichen Ports. | N, P |
| 4 | Netzwerke korrekt isoliert. | N, P |
| 5 | TLS gültig. | N, P |
| 6 | mTLS funktionsfähig. | N, P |
| 7 | Nginx funktionsfähig. | N, P |
| 8 | Envoy funktionsfähig. | N, P |
| 9 | Postfix funktionsfähig. | N, P |
| 10 | n8n funktionsfähig. | N, P |
| 11 | FastAPI funktionsfähig. | N, P |
| 12 | PostgreSQL funktionsfähig. | N, P |
| 13 | Worker funktionsfähig. | N, P |
| 14 | Statuspage funktionsfähig. | N, P |
| 15 | Reproduzierbarer Release-Build. | O, U, D; F für formalen Git-Release |
| 16 | Eindeutige Releaseidentität. | O, U, D; F für formalen Git-Release |
| 17 | Verifizierte Containerimages. | N, O, U, D |
| 18 | Release-Manifest. | O, U, D; F für formalen Git-Release |
| 19 | SBOM. | N, O, U, D |
| 20 | Konfigurationsschema. | N, O, U, D |
| 21 | Secrets sicher bereitgestellt. | N, O, U, D |
| 22 | Zertifikate sicher bereitgestellt. | N, O, U, D |
| 23 | Preflight erfolgreich. | N, O, U, D |
| 24 | Keine unsicheren Standardwerte. | N, O, U, D |
| 25 | Kontrollierte Startreihenfolge. | N, O, U, D |
| 26 | Deployment-Lock. | N, O, U, D |
| 27 | Keine unautorisierten Produktivänderungen. | N, O, U, D |
| 28 | Rollbackverfahren dokumentiert. | N, O, U, D |
| 29 | Fachliche Datenbank vorhanden. | N, R, U, P |
| 30 | n8n-Datenbanktrennung vorhanden. | N, R, U, P |
| 31 | Rollen korrekt. | N, R, U, P |
| 32 | Runtime-Rechte minimal. | N, R, U, P |
| 33 | Migrationen erfolgreich. | N, R, U, P |
| 34 | Keine parallelen Migrationen. | N, R, U, P |
| 35 | Migrationsstand verifiziert. | N, R, U, P |
| 36 | Persistente Volumes korrekt. | N, R, U, P |
| 37 | Backup vorhanden. | N, R, U, P |
| 38 | Backupintegrität geprüft. | N, R, U, P |
| 39 | Restore erfolgreich. | N, R, U, P |
| 40 | Daten nach Restore konsistent. | N, R, U, P |
| 41 | Anmeldung funktioniert. | B, P |
| 42 | MFA funktioniert. | B, P |
| 43 | Sessions funktionieren. | B, P |
| 44 | Logout funktioniert. | B, P |
| 45 | CSRF funktioniert. | B, P |
| 46 | RBAC funktioniert. | B, P |
| 47 | Objektberechtigungen funktionieren. | B, P |
| 48 | Server-ACLs funktionieren. | B, P |
| 49 | Berechtigungsentzug funktioniert. | B, P |
| 50 | Kein IDOR. | B, P |
| 51 | Keine Selbsteskalation. | B, P |
| 52 | Keine unzulässige technische Tokenverwendung. | B, P |
| 53 | Serverregistrierung funktioniert. | B, P |
| 54 | Server-UUID stabil. | B, P |
| 55 | Serverbearbeitung funktioniert. | B, P |
| 56 | Archivierung funktioniert. | B, P |
| 57 | Gruppenverwaltung funktioniert. | B, P |
| 58 | Mehrfachmitgliedschaften funktionieren. | B, P |
| 59 | Primärgruppen funktionieren. | B, P |
| 60 | Manuelle Sortierung funktioniert. | B, P |
| 61 | Keine Berechtigungsvererbung durch Servergruppen. | B, P |
| 62 | Ansible Collect funktioniert. | B, P, R |
| 63 | Inventar-JSON entspricht dem Schema. | B, P, R |
| 64 | Ansible Submit funktioniert. | B, P, R |
| 65 | mTLS-Authentifizierung funktioniert. | B, P, R |
| 66 | Technische Tokenbindung funktioniert. | B, P, R |
| 67 | Server-Scope korrekt. | B, P, R |
| 68 | HTTP 202 korrekt. | B, P, R |
| 69 | Staging persistent. | B, P, R |
| 70 | Inventory Processor funktioniert. | B, P, R |
| 71 | Normalisierung korrekt. | B, P, R |
| 72 | Snapshots unveränderlich. | B, P, R |
| 73 | Snapshot-Historie korrekt. | B, P, R |
| 74 | Dashboard-Upload funktioniert. | B, P, R |
| 75 | Upload-RBAC funktioniert. | B, P, R |
| 76 | Upload-Idempotenz funktioniert. | B, P, R |
| 77 | Keine Serverregistrierung durch Upload. | B, P, R |
| 78 | Keine Gruppenänderung durch Upload. | B, P, R |
| 79 | Keine ACL-Änderung durch Upload. | B, P, R |
| 80 | CVE Collector funktioniert. | B, P, R |
| 81 | Quellprovenienz vorhanden. | B, P, R |
| 82 | CVE-Aktualisierung funktioniert. | B, P, R |
| 83 | CVE Enricher funktioniert. | B, P, R |
| 84 | Revisionen nachvollziehbar. | B, P, R |
| 85 | Matching Engine funktioniert. | B, P, R |
| 86 | Affected korrekt. | B, P, R |
| 87 | Not Affected korrekt. | B, P, R |
| 88 | Unknown korrekt. | B, P, R |
| 89 | Debian/Ubuntu-Versionssemantik korrekt. | B, P, R |
| 90 | Vendor-Backport-Fälle korrekt. | B, P, R |
| 91 | Matching-Provenienz vorhanden. | B, P, R |
| 92 | Matching-Idempotenz funktioniert. | B, P, R |
| 93 | Keine falsche Entwarnung. | B, P, R |
| 94 | Finding-Erzeugung funktioniert. | B, P, R |
| 95 | Finding-Identität stabil. | B, P, R |
| 96 | Triage funktioniert. | B, P, R |
| 97 | Zuständigkeiten funktionieren. | B, P, R |
| 98 | Risikoausnahmen funktionieren. | B, P, R |
| 99 | Technischer Status bleibt korrekt. | B, P, R |
| 100 | Resolution funktioniert. | B, P, R |
| 101 | Reopening funktioniert. | B, P, R |
| 102 | Finding-Historie erhalten. | B, P, R |
| 103 | Audit vollständig. | B, P, R |
| 104 | Outbox funktioniert. | B, P |
| 105 | Notification Worker funktioniert. | B, P |
| 106 | Notification-Regeln funktionieren. | B, P |
| 107 | n8n-Workflow funktioniert. | B, P |
| 108 | SMTP-Adapter funktioniert. | B, P |
| 109 | Postfix-Annahme funktioniert. | B, P |
| 110 | Envoy-Egress funktioniert. | B, P |
| 111 | Kontrollierte Testzustellung funktioniert. | B, P |
| 112 | Deduplizierung funktioniert. | B, P |
| 113 | Keine unkontrollierten Retries. | B, P |
| 114 | Keine falsche Zustellbestätigung. | B, P |
| 115 | Keine Alarmrekursion. | B, P |
| 116 | Dashboard erreichbar. | N, B, P |
| 117 | Navigation funktioniert. | N, B, P |
| 118 | Serveransichten funktionieren. | N, B, P |
| 119 | Findingansichten funktionieren. | N, B, P |
| 120 | Administrative Formulare funktionieren. | N, B, P |
| 121 | Berechtigungssichere Kennzahlen. | N, B, P |
| 122 | Statuspage erreichbar. | N, B, P |
| 123 | Liveness korrekt. | N, B, P |
| 124 | Readiness korrekt. | N, B, P |
| 125 | Functional Health korrekt. | N, B, P |
| 126 | Workerstatus korrekt. | N, B, P |
| 127 | Jobrückstände korrekt. | N, B, P |
| 128 | Monitoring-Freshness korrekt. | N, B, P |
| 129 | Incidents korrekt. | N, B, P |
| 130 | Keine falschen Healthy-Zustände. | N, B, P |
| 131 | Docker-Hardening geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 132 | Netzwerkisolation geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 133 | TLS geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 134 | mTLS geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 135 | Secrets geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 136 | Authentifizierung geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 137 | MFA geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 138 | RBAC geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 139 | CSRF geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 140 | Uploadsicherheit geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 141 | Datenbankrechte geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 142 | Egress-Sicherheit geprüft. | U, N, P; aktuelle Image-/Dependencygates |
| 143 | Dependency Scanning. | U, N, P; aktuelle Image-/Dependencygates |
| 144 | Image Scanning. | U, N, P; aktuelle Image-/Dependencygates |
| 145 | Secret Scanning. | U, N, P; aktuelle Image-/Dependencygates |
| 146 | Keine freigabeverhindernden Sicherheitsbefunde. | U, N, P; aktuelle Image-/Dependencygates |
| 147 | Performancebaseline vorhanden. | P; identische Artefakte, Phase-23-Budgets |
| 148 | Leistungsbudgets definiert. | P; identische Artefakte, Phase-23-Budgets |
| 149 | API-Lasttest erfolgreich. | P; identische Artefakte, Phase-23-Budgets |
| 150 | Datenbank-Lasttest erfolgreich. | P; identische Artefakte, Phase-23-Budgets |
| 151 | Upload-Lasttest erfolgreich. | P; identische Artefakte, Phase-23-Budgets |
| 152 | Matching-Lasttest erfolgreich. | P; identische Artefakte, Phase-23-Budgets |
| 153 | Worker-Lasttest erfolgreich. | P; identische Artefakte, Phase-23-Budgets |
| 154 | Frontend-Lasttest erfolgreich. | P; identische Artefakte, Phase-23-Budgets |
| 155 | Keine fachlichen Regressionen. | P; identische Artefakte, Phase-23-Budgets |
| 156 | Workerabsturz korrekt behandelt. | R, O, P, D |
| 157 | PostgreSQL-Neustart korrekt behandelt. | R, O, P, D |
| 158 | Envoy-Ausfall korrekt behandelt. | R, O, P, D |
| 159 | n8n-Ausfall korrekt behandelt. | R, O, P, D |
| 160 | Postfix-Ausfall korrekt behandelt. | R, O, P, D |
| 161 | Recovery erfolgreich. | R, O, P, D |
| 162 | Restore erfolgreich. | R, O, P, D |
| 163 | RPO/RTO bewertet. | R, O, P, D |
| 164 | Rollbackverfahren geprüft. | R, O, P, D |
| 165 | Architektur dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 166 | Deployment dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 167 | Konfiguration dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 168 | Secrets dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 169 | Zertifikate dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 170 | Migrationen dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 171 | Updates dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 172 | Rollback dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 173 | Backup dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 174 | Restore dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 175 | Betriebsprozesse dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 176 | Incident Response dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 177 | Administratorhandbuch vollständig. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 178 | Benutzerhandbuch vollständig. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 179 | Testmatrix vollständig. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 180 | Testergebnisse dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 181 | Sicherheitsbefunde dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 182 | Restrisiken dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht |
| 183 | Release-Manifest vollständig. | D, U; tatsächliche Ergebnisse im Maschinenbericht; F (Gitbezug noch offen) |
| 184 | Go-/No-Go-Entscheidung dokumentiert. | D, U; tatsächliche Ergebnisse im Maschinenbericht; F (Gitbezug noch offen) |
| 185 | Produktivfreigabe nur nach ausdrücklicher Genehmigung. | U; Produktion gesperrt, F erst nach konkreter Genehmigung |
| 186 | Finaler Release-Stand nachvollziehbar. | D, U; tatsächliche Ergebnisse im Maschinenbericht; F (Gitbezug noch offen) |

## 105 verbindliche Invarianten

| ID | Regel | Nachweise |
|---|---|---|
| DEP-001 | Bestehende Architektur beibehalten | P, N, D |
| DEP-002 | Keine neue Datenbanktechnologie | P, N, D |
| DEP-003 | Kein Redis | P, N, D |
| DEP-004 | Kein zusätzlicher Message Broker | P, N, D |
| DEP-005 | Keine zweite Workflow-Engine | P, N, D |
| DEP-006 | Docker Compose bleibt Grundlage | P, N, D |
| DEP-007 | Nginx bleibt HTTPS-Eingang | P, N, D |
| DEP-008 | Envoy bleibt kontrollierter Egress | P, N, D |
| DEP-009 | Postfix bleibt interner Mailrelay | P, N, D |
| DEP-010 | n8n bleibt vorhandener Orchestrator | P, N, D |
| DEP-011 | PostgreSQL bleibt fachliche Datenhaltung | P, N, D |
| DEP-012 | Bestehendes FastAPI verwenden | P, N, D |
| DEP-013 | Bestehende PostgreSQL-Worker verwenden | P, N, D |
| DEP-014 | Bestehende Transactional Outbox verwenden | P, N, D |
| DEP-015 | Keine ungeplanten Fachfunktionen | P, N, D |
| DEP-016 | Keine ungeplante Frameworkmigration | P, N, D |
| DEP-017 | Keine ungeplante Container-Orchestrierung | P, N, D |
| DEP-018 | Release-Identität eindeutig | U, O, D; F für formalen Release |
| DEP-019 | Image-Digests verifizierbar | U, O, D; F für formalen Release |
| DEP-020 | Release-Manifest vorhanden | U, O, D; F für formalen Release |
| DEP-021 | Konfigurationsschema validiert | U, O, D; F für formalen Release |
| DEP-022 | Keine produktiven Secrets im Repository | U, O, D; F für formalen Release |
| DEP-023 | Keine Secrets in Images | U, O, D; F für formalen Release |
| DEP-024 | Keine Secrets in Buildlogs | U, O, D; F für formalen Release |
| DEP-025 | Keine unsicheren Standardpasswörter | U, N, R, P, D |
| DEP-026 | Keine unsicheren TLS-Fallbacks | U, N, R, P, D |
| DEP-027 | mTLS-Identitäten erhalten | U, N, R, P, D |
| DEP-028 | Technische Tokens servergebunden | U, N, R, P, D |
| DEP-029 | Tokenwiderruf möglich | U, N, R, P, D |
| DEP-030 | Keine automatische produktive Secret-Rotation | U, N, R, P, D |
| DEP-031 | PostgreSQL-Rechte minimal | U, N, R, P, D |
| DEP-032 | n8n-Datenbanktrennung bleibt erhalten | U, N, R, P, D |
| DEP-033 | Migrationen kontrolliert | U, N, R, P, D |
| DEP-034 | Keine parallelen Migrationen | U, N, R, P, D |
| DEP-035 | Keine ungeprüften Datenbank-Downgrades | U, N, R, P, D |
| DEP-036 | Backup vor risikoreichen Migrationen | U, N, R, P, D |
| DEP-037 | Keine Volumelöschung beim Rollback | U, N, R, P, D |
| DEP-038 | Kein Docker Socket in Plattformdiensten | U, N, R, P, D |
| DEP-039 | Keine unnötigen öffentlichen Ports | U, N, R, P, D |
| DEP-040 | Keine unnötigen privilegierten Container | U, N, R, P, D |
| DEP-041 | Netzwerkisolation erhalten | U, N, R, P, D |
| DEP-042 | Kein Egress-Bypass | U, N, R, P, D |
| DEP-043 | Keine freie SMTP-Schnittstelle | U, N, R, P, D |
| DEP-044 | Keine direkte SSH-Verbindung zu inventarisierten Servern | B, P, D |
| DEP-045 | Technische Inventaraufnahme über Ansible | B, P, D |
| DEP-046 | Kein Serveranlegen durch Upload | B, P, D |
| DEP-047 | Keine Gruppenänderung durch Upload | B, P, D |
| DEP-048 | Keine ACL-Änderung durch Upload | B, P, D |
| DEP-049 | HTTP 202 bedeutet persistente Annahme | B, P, D |
| DEP-050 | HTTP 202 bedeutet nicht vollständige Verarbeitung | B, P, D |
| DEP-051 | Inventarsnapshots unveränderlich | B, P, D |
| DEP-052 | CVE-Quellprovenienz erhalten | B, P, D |
| DEP-053 | Enrichment-Revisionen erhalten | B, P, D |
| DEP-054 | Matching-Evidenz erhalten | B, P, D |
| DEP-055 | Unknown ist keine Entwarnung | B, P, D |
| DEP-056 | Finding-Historien erhalten | B, P, D |
| DEP-057 | Risikoakzeptanz ist kein Fixnachweis | B, P, D |
| DEP-058 | Reopening bleibt möglich | B, P, D |
| DEP-059 | Notification-Verarbeitung idempotent | B, P, D |
| DEP-060 | Postfix-Annahme ist keine Zustellbestätigung | B, P, D |
| DEP-061 | Keine Alarmrekursion | B, P, D |
| DEP-062 | Keine unkontrollierten Retry-Stürme | B, P, D |
| DEP-063 | Worker-Leases beachten | B, P, D |
| DEP-064 | Fencing beachten | B, P, D |
| DEP-065 | Outbox konsistent | B, P, D |
| DEP-066 | Fachliche Transaktionen atomar | B, P, D |
| DEP-067 | Bestehende Authentifizierung verwenden | B, P, D |
| DEP-068 | Bestehende MFA verwenden | B, P, D |
| DEP-069 | Bestehendes RBAC verwenden | B, P, D |
| DEP-070 | Objektberechtigungen serverseitig | B, P, D |
| DEP-071 | CSRF für Browsermutationen | B, P, D |
| DEP-072 | Keine Selbsteskalation | B, P, D |
| DEP-073 | Keine impliziten ACLs durch Servergruppen | B, P, D |
| DEP-074 | Berechtigungssichere Dashboardkennzahlen | B, P, D |
| DEP-075 | Berechtigungssichere Exporte | B, P, D |
| DEP-076 | Keine produktiven Testbenachrichtigungen ohne Freigabe | B, P, D |
| DEP-077 | Statuspage-Freshness berücksichtigen | B, P, D |
| DEP-078 | Kein falsches Healthy | B, P, D |
| DEP-079 | Staging vor Produktion | U, N, R, O, D; F für Produktion |
| DEP-080 | Keine Produktivfreigabe ohne Pflichtnachweise | U, N, R, O, D; F für Produktion |
| DEP-081 | Kein produktiver Deploymentstart ohne ausdrückliche Freigabe | U, N, R, O, D; F für Produktion |
| DEP-082 | Deployment-Preflight ist standardmäßig lesend | U, N, R, O, D; F für Produktion |
| DEP-083 | Deployment-Lock verwenden | U, N, R, O, D; F für Produktion |
| DEP-084 | Rollbackpfad dokumentiert | U, N, R, O, D; F für Produktion |
| DEP-085 | Recoverypfad dokumentiert | U, N, R, O, D; F für Produktion |
| DEP-086 | Backupintegrität prüfen | U, N, R, O, D; F für Produktion |
| DEP-087 | Restore isoliert testen | U, N, R, O, D; F für Produktion |
| DEP-088 | n8n-Verschlüsselungsmaterial im Recovery berücksichtigen | U, N, R, O, D; F für Produktion |
| DEP-089 | RPO/RTO nicht erfinden | U, N, R, O, D; F für Produktion |
| DEP-090 | Performancebudgets aus Phase 23 verwenden | P, B, R, D |
| DEP-091 | Keine fachlichen Regressionen durch Optimierung | P, B, R, D |
| DEP-092 | Keine produktiven Lasttests ohne Freigabe | P, B, R, D |
| DEP-093 | Kein automatischer CVE-Full-Sync beim Test | P, B, R, D |
| DEP-094 | Keine synthetischen Produktivdaten | P, B, R, D |
| DEP-095 | Keine verlorenen Audit-Ereignisse | P, B, R, D |
| DEP-096 | Keine unkontrollierte Historienlöschung | P, B, R, D |
| DEP-097 | Keine produktiven Secrets in Staging | U, N, R, D; tatsächlicher Maschinenbericht |
| DEP-098 | Vollständige Release-Dokumentation | U, N, R, D; tatsächlicher Maschinenbericht |
| DEP-099 | Vollständige Testnachweise | U, N, R, D; tatsächlicher Maschinenbericht |
| DEP-100 | Fehlgeschlagene Tests ehrlich dokumentieren | U, N, R, D; tatsächlicher Maschinenbericht |
| DEP-101 | Kritische Befunde als No-Go behandeln | U, N, R, D; tatsächlicher Maschinenbericht |
| DEP-102 | Offene Restrisiken dokumentieren | U, N, R, D; tatsächlicher Maschinenbericht |
| DEP-103 | Keine formale Zertifizierung ohne Nachweis behaupten | U, N, R, D; tatsächlicher Maschinenbericht |
| DEP-104 | Keine Git-Commits ohne Auftrag | Kein Commit/Push ausgeführt; ausdrücklicher Auftrag erforderlich |
| DEP-105 | Kein Git-Push ohne Auftrag | Kein Commit/Push ausgeführt; ausdrücklicher Auftrag erforderlich |

## Befunde und Einschränkungen

Die beiden Restorekorrekturen sind erforderlich: PostgreSQL normalisiert manche
n8n-Arraycasts beim Dump/Restore syntaktisch, und Rollen-GUCs sind nicht Teil eines
Datenbankdumps. Der Vergleich normalisiert ausschließlich nachgewiesene äquivalente
unbeschränkte varchar-Literale; ACLs, Eigentümer, Werte und Operatoren bleiben strikt.
Rollen-GUCs werden ausdrücklich gesichert/restauriert und anschließend verglichen.
Vorläufe sind keine Erfolge. Der aktuelle Native-JUnit muss ohne Fehler/Skip
vollständig bestehen und zum im Bericht angegebenen Sourcehash gehören.

Phase-23-p95 bei 100/1000/10000 Objekten: 237,5/215,3/200,8 ms ohne APIfehler.
Die damalige Baseline war 4186/4214/4107 ms mit 36 HTTP503. Diese Werte gelten für
die geprüfte lokale Konfiguration. Die neue Stagingkampagne ist keine erneute
Produktionslastmessung. Unabhängige Produktionskapazität, Offsite-Key-Recovery,
Betreiberkontakte, Produktions-PKI/Secrets und explizite Freigabe bleiben
Voraussetzungen für einen späteren echten Produktivstart.
