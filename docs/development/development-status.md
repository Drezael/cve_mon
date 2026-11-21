# Entwicklungsfortschritt

Stand: 06.11.2026. **Phasen 0–10: completed; lokal abgenommen.**
Die vollständige Umsetzung wurde vom Nutzer beauftragt. Aktuelle Nachweise stehen in den jeweiligen Phasenabnahmen; die ursprüngliche Phase-1-Tabelle bleibt historisch erhalten.
Alle Ergebnisse beziehen sich auf die lokale Linux-/Python-3.12-Entwicklungsumgebung.
Ein gehosteter GitHub-Lauf steht bis zur Veröffentlichung aus; lokale CI-Prüfungen sind erfolgreich.

Historischer Ausgangsbestand der ursprünglichen Phase 1 war ausschließlich
`docs/history/plans/phase_01.md`; die damals neuen Artefakte sind unten aufgeführt.
Die nachgereichte Phase 0 ergänzt Verträge und korrigiert bestehende Phase-1-Dateien
gemäß Auswirkungsbericht. Beide Originalkonzepte sind unverändert.
Die vollständige Dateiliste und Einschränkungen stehen im [Abnahmebericht](phase-01-acceptance.md).

| Aufgabe | Titel | Status | Abhängigkeiten | Ergebnis | Neue Dateien / Artefakte | Teststatus | Abschluss |
|---|---|---|---|---|---|---|---|
| T01.01.01 | Repository analysieren | completed | — | Ausgangsbestand: nur Phasenkonzept, kein Git; keine Konflikte. | Keine | Bestands- und Versionsabfragen erfolgreich | 05.11.2026 |
| T01.01.02 | Projektverzeichnisse erstellen | completed | T01.01.01 | Alle Bereiche und getrennte Upload-/Administrationspfade vorbereitet. | Bereichs-README-Dateien gemäß Dateiliste | Strukturtests und Validator erfolgreich | 05.11.2026 |
| T01.01.03 | Git-Konfiguration erstellen | completed | T01.01.02 | Git initialisiert (main); lokale Daten und Secrets ausgeschlossen. | .gitignore, .editorconfig | 19 Ignore-Fälle und versionierbare Vorlagen geprüft | 05.11.2026 |
| T01.01.04 | Projekt-README erstellen | completed | T01.01.02 | Projektziel, geplanter Umfang und tatsächlicher Status dokumentiert. | README.md | Inhalte und lokale Dokumentationslinks geprüft | 05.11.2026 |
| T01.01.05 | Umgebungsvorlage erstellen | completed | T01.01.03 | Drei unkritische, dokumentierte Variablen. | .env.example | Vorlagen- und Dokumentationstest erfolgreich | 05.11.2026 |
| T01.02.01 | Python-Basisversion festlegen | completed | T01.01.01 | Python 3.12 verbindlich; lokal 3.12.3. | Dokumentation und Versionsprüfung im Bootstrap | Versionstest und Ablehnung falscher Version erfolgreich | 05.11.2026 |
| T01.02.02 | pyproject.toml erstellen | completed | T01.02.01 | Zentrale Werkzeugkonfiguration ohne produktives Paket. | pyproject.toml | TOML-, Ruff-, Mypy- und Pytest-Prüfung erfolgreich | 05.11.2026 |
| T01.02.03 | Entwicklungsabhängigkeiten festlegen | completed | T01.02.02 | Direkte und transitive Versionen exakt gesperrt, SHA-256-Hashes. | requirements/dev.in, requirements/dev.txt | Frische Hash-Installation und pip check erfolgreich | 05.11.2026 |
| T01.02.04 | Entwicklungs-Bootstrap implementieren | completed | T01.02.03 | Idempotentes Setup ohne Root und globale Paketinstallation. | scripts/bootstrap_dev.sh | Frisch-/Wiederholungssetup und drei Fehlerfalltests erfolgreich | 05.11.2026 |
| T01.03.01 | Ruff konfigurieren | completed | T01.02.02 | Python 3.12, 100 Zeichen, E/F/I/B/UP/SIM. | Konfiguration in pyproject.toml | make lint, format und format-check erfolgreich | 05.11.2026 |
| T01.03.02 | Mypy konfigurieren | completed | T01.02.02 | Strikte Prüfung von Skripten und Tests; explizite Namespace-Basis. | Konfiguration in pyproject.toml | make typecheck erfolgreich (10 Dateien) | 05.11.2026 |
| T01.03.03 | Coding-Standards dokumentieren | completed | T01.03.01, T01.03.02 | Benennung, Typen, Fehler, Logging, APIs und Sicherheit beschrieben. | docs/development/coding-standards.md | Mit Phasenarchitektur abgeglichen | 05.11.2026 |
| T01.04.01 | Pytest konfigurieren | completed | T01.02.03 | Testpfad, Marker und isolierte Fixtures. | tests/conftest.py, Konfiguration in pyproject.toml | 117 Tests erkannt und erfolgreich | 05.11.2026 |
| T01.04.02 | Repository- und Konfigurationstests | completed | T01.04.01 | Struktur, Konfiguration, Ignore-Regeln, Bootstrap und Scanner geprüft. | tests/unit/test_*.py gemäß Dateiliste | 117 positive/negative Tests erfolgreich | 05.11.2026 |
| T01.04.03 | YAML- und JSON-Validierung | completed | T01.02.03, T01.04.02 | YAML/JSON, Schemas, OpenAPI, Beispiele und Sicherheitsinvarianten. | scripts/validate_repository.py, scripts/validate_contracts.py, Vertragsmanifest, .yamllint.yml | YAML/JSON/Schemas, Inventarbeispiele, OpenAPI und Auth-/Netzinvarianten geprüft | 05.11.2026 |
| T01.04.04 | Secret-Scanning | completed | T01.02.03, T01.04.02 | Lokaler Scanner ohne Netzwerkverifikation; Baseline bleibt unverändert. | scripts/scan_secrets.py, .secrets.baseline, tests/unit/test_security.py | Neue/versionierte Test-Secrets und Baseline-Metadaten getestet | 05.11.2026 |
| T01.04.05 | CI-Qualitätsprüfung | completed | T01.03.01, T01.03.02, T01.04.03, T01.04.04 | CI mit read-only Berechtigungen und gepinnten Actions. | .github/workflows/quality.yml | YAML-/Workflowtests, SHA-Abgleich und lokale CI-Befehle erfolgreich | 05.11.2026 |
| T01.05.01 | Makefile | completed | T01.02.04, T01.04.05 | Alle zehn geforderten Entwicklerbefehle. | Makefile | Alle Targets ausgeführt; absichtliche Fehler stoppen make check | 05.11.2026 |
| T01.05.02 | Repository-Validator | completed | T01.01.02, T01.04.03 | Pflichtpfade und Konfigurationen mit Fehlerstatus geprüft. | scripts/validate_repository.py | Entfernte Pflichtdatei in temporärer Kopie erkannt | 05.11.2026 |
| T01.05.03 | Entwicklerdokumentation | completed | T01.05.01, T01.05.02 | Setup, Fortschritt und Umsetzungsplan dokumentiert. | docs/development/developer-setup.md, development-status.md, phase-01-plan.md | Einrichtung in frischer Kopie nach dokumentiertem Verfahren erfolgreich | 05.11.2026 |
| T01.05.04 | Gesamtabnahme | completed | T01.01–T01.04, T01.05.01–03 | Gesamtabnahme mit allen A01–A20-Nachweisen. | docs/development/phase-01-acceptance.md | make check und 19 zusätzliche Abnahmeschritte erfolgreich | 05.11.2026 |
| T01.05.05 | Phase-1-Freigabe und Übergabe | completed | T01.05.04 | Phase 1 nach vollständiger Phase-0-Integration erneut lokal freigegeben. | Übergabe im Abnahmebericht und Fortschrittsdatei | Alle 22 Aufgaben und Abnahmematrix kontrolliert | 05.11.2026 |

## Historische Phase-1-Voraussetzungen und Einschränkungen

Keine offenen verpflichtenden lokalen Phase-1-Prüfungen. Die Fachanwendung ist noch nicht implementiert.
Phase-0-Verträge und logisches Datenmodell sind jetzt vorhanden, integriert und geprüft.
Gesamtkonzept 3.12 und Entwicklungsplan 1.2 als separate Originale sowie das konkrete
Phase-2-Konzept bleiben vor Folgearbeiten bereitzustellen und abzugleichen.
Git-Remote, erster Commit und Push sind nicht eingerichtet beziehungsweise nicht ausgeführt;
ein gehosteter CI-Lauf ist daher noch nicht möglich. Es wurden keine Container gestartet
und keine externen Ansible-Dateien geändert.

## Nachgeholte Phase 0

Alle 33 Phase-0-Aufgaben sind spezifiziert; [Phase-0-Status](phase-00-status.md).
Der [Auswirkungsbericht](phase-01-impact.md) dokumentiert die korrigierten Phase-1-Aufgaben.
117 Tests, frisches/repetiertes Setup und alle 19 Abnahmeschritte erfolgreich.
Die ursprüngliche Dateiliste der Erstabnahme ist historisch, die aktuelle Liste steht in der Phase-0-Abnahme.

## Phase 2

35 Infrastrukturaufträge abgeschlossen; [Abnahme](phase-02-acceptance.md).
142 Standardtests plus 40 reale Docker-Tests erfolgreich. Host-/PKI-Betriebsfreigaben vor Produktion offen.

## Phase 3

Vollständige Datenbankumsetzung und Nachweise: [Status](phase-03-status.md), [Abnahme](phase-03-acceptance.md), [Übergabe](phase-03-handover.md).

## Phase 4

Phase 4 vollständig implementiert und lokal abgenommen (473 Tests inklusive Regression).
Envoy-Egress einschließlich DNS-/SSRF-/SMTP-Nachweisen: [Status](phase-04-status.md), [Abnahme](phase-04-acceptance.md), [Übergabe](phase-04-handover.md).

## Phase 5

Postfix mit gesicherter SMTP-Kette und persistenter Queue abgeschlossen;
[Abnahme](phase-05-acceptance.md), [Übergabe](phase-05-handover.md).

## Phase 6

Installierbare Python-Basis und interner API-Dienst vollständig umgesetzt und lokal abgenommen.
622 Tests einschließlich Regression, alle Qualitätsprüfungen erfolgreich.
[Status](phase-06-status.md), [Abnahme](phase-06-acceptance.md), [Übergabe](phase-06-handover.md).
Fachendpunkte, Jobs/Outbox und Authentifizierung bleiben Folgephasen. Remote-CI noch nicht ausgeführt.

## Phase 7

Persistente PostgreSQL-Jobs, Worker mit Leases/Fencing, Retry/Recovery und transaktionale
Outbox mit eigenem internem Dispatcher vollständig umgesetzt und lokal abgenommen.
Alle 45 Aufträge, 51 Schlusskriterien und 48 Invarianten nachgewiesen; 687 Tests inklusive
vollständiger Regression erfolgreich. [Abnahme](phase-07-acceptance.md),
[Status](phase-07-status.md), [Übergabe](phase-07-handover.md).
Keine fachlichen Handler oder Zustellziele produktiv aktiviert. Phase 8 bleibt Folgearbeit.

## Phase 8

Lokale Authentifizierung, Argon2id, serverseitige Sessions/CSRF, Administrator-TOTP-MFA,
kontrollierte Recovery-/Reset-Grundlage und Audit/Outbox vollständig umgesetzt.
Alle 45 Aufträge, 66 Pflichtprüfungen und 50 Auth-Invarianten nachgewiesen. 781 Tests
einschließlich vollständiger Regression erfolgreich. [Abnahme](phase-08-acceptance.md),
[Status](phase-08-status.md), [Übergabe](phase-08-handover.md).
Keine automatischen Administratorkonten oder öffentliche Reset-Zustellung. Phase 9 wurde anschließend umgesetzt; siehe folgenden Abschnitt.

## Phase 9

Benutzerverwaltung, vier endliche Systemrollen, kontrollierte zusätzliche Rollen und explizite
Server-ACLs vollständig umgesetzt. Zentraler Principal/Default Deny, SQL-Filter, aktuelle
Reauthentifizierung, native transaktionale Letzter-Admin-Invariante, Recovery sowie Audit/Outbox.
45 Aufträge, 66 Pflichtprüfungen, 50 RBAC-Invarianten und 45 Schlusskriterien nachgewiesen.
863 Tests einschließlich vollständiger Regression erfolgreich; API 0.9.0, Migration 00015.
[Abnahme](phase-09-acceptance.md), [Status](phase-09-status.md), [Übergabe](phase-09-handover.md).
Phase 10 wurde anschließend umgesetzt; siehe folgenden Abschnitt.

## Phase 10

Administrative Server-/Gruppenverwaltung, stabile UUIDs, explizite Mehrfachmitgliedschaften
mit Primärgruppe und drei unabhängige manuelle Sortierkontexte vollständig implementiert.
Native Constraints, If-Match/CAS, aktuelle MFA/Reauth, SQL-ACL-Listen und atomare Audit/Outbox.
Alle 45 Aufträge, 78 Pflichtprüfungen, 55 SRV-Invarianten und 47 Schlusskriterien nachgewiesen.
972 Tests einschließlich vollständiger Regression bestanden. API 0.10.0 und Revision 00016 aktiv.
[Abnahme](phase-10-acceptance.md), [Status](phase-10-status.md), [Übergabe](phase-10-handover.md).
Phase 11 wurde anschließend umgesetzt; siehe folgenden Abschnitt.

## Phase 11

Getrennter technischer mTLS-/Token- und Dashboard-Session-/MFA-/CSRF-Upload vollständig
implementiert. Gemeinsamer begrenzter Validator, unveränderliche persistente Annahme,
kanonische Idempotenz und autorisierter Status; keine Verarbeitung vor Phase 14.
45 Aufträge, 95 Pflichtprüfungen, 61 INVUP-Invarianten und 61 Schlusskriterien nachgewiesen.
1089 Tests einschließlich vollständiger Regression bestanden. API 0.11.0 und Revision 00017 aktiv.
[Abnahme](phase-11-acceptance.md), [Status](phase-11-status.md), [Übergabe](phase-11-handover.md).
Phase 12 wurde anschließend umgesetzt; siehe folgenden Abschnitt. Externes Ansible-Projekt unverändert; Remote-CI nicht ausgeführt.

## Phase 12

Lesende Ansible-Inventarisierung im vorhandenen Drezael/ansible-Repository vollständig
umgesetzt: Launcher/Vault/SSH/sudo, OS/Hardware, vollständige Pakete, Dienste und lokale
Docker-Metadaten. Sichere lokale JSON-Historie, keine automatische Übermittlung.
Alle 45 Aufträge, 105 Pflichtprüfungen, 60 COL-Invarianten und 60 Schlusskriterien nachgewiesen.
1291 Tests bestanden: 189 Ansible- und 1102 CVE-Prüfungen einschließlich Regression.
Gemeinsamer Vertrag 1.1, ursprüngliches 1.0 unverändert; API 0.11.1, Revision 00018 aktiv.
[Abnahme](phase-12-acceptance.md), [Übergabe](phase-12-handover.md). Phase 13 wurde anschließend umgesetzt; siehe folgenden Abschnitt.

## Phase 13

Sicherer controllerseitiger Ansible Submit vollständig implementiert: mTLS/Vaulttoken,
Originalbytes, stabile Idempotenz, begrenzter Retry, atomare Receipts und geschützter Status.
Expliziter Batch mit Fehlerisolierung, keine automatische Erfassung oder Fachverarbeitung.
Alle 45 Aufträge, 138 Pflichtprüfungen, 75 SUB-Invarianten und 65 Schlusskriterien nachgewiesen.
879 Tests bestanden, einschließlich vorhandener Collect-/Launcher- und vollständiger Upload-
Regression. API 0.11.1 und Revision 00018 unverändert. [Abnahme](phase-13-acceptance.md),
[Übergabe](phase-13-handover.md). Phase 14 wurde anschließend implementiert; siehe folgenden Abschnitt.

## Phase 14

Inventory Processor mit registrierten PostgreSQL-Jobs, begrenzter Revalidierung und
Normalisierung, versiegelten Snapshots, Historie, transaktionalem Current-Pointer und
Audit/Outbox implementiert. Alle 45 Aufgaben lokal abgenommen, 934 unterschiedliche relevante Tests nachgewiesen.
Revision 00019 und cve-inventory 0.14.0 aktiv; sieben eigene Dienste gesund. Schemaeingänge und Annahme-Receipts bleiben kompatibel;
keine administrativen Änderungen oder vorgezogenen Matching-/Finding-Funktionen.
[Abnahme](phase-14-acceptance.md), [Status](phase-14-status.md), [Übergabe](phase-14-handover.md).

## Phase 15

Quellengetrennter CVE Importer 0.15.0 für CVEProject, NVD, CISA KEV, Ubuntu und OSV
implementiert und lokal abgenommen. Alle 45 Aufträge, 128 Pflichtkriterien und 70 IMP-Invarianten
zugeordnet; 1.053 unterschiedliche relevante Fälle bestanden. Revision 00020 und der achte
Dienst sind aktiv; alle acht Dienste gesund. Originaldaten/Revisionen/Provenienz/Aliase,
Envoy-Downloads, begrenzte Parser, unabhängige Cursor und gefencte Recovery sind vorhanden.
Keine automatische Quellenfusion, Anreicherung, Matching oder Findings; Quellimporte bleiben explizit.
[Abnahme](phase-15-acceptance.md), [Status](phase-15-status.md), [Übergabe](phase-15-handover.md).

## Phase 16

CVE Enricher 0.16.0 für fünf persistierte Quellen, explizite CVE-/Advisory-Identitäten,
feldbezogene Provenienz, CVSS 2/3/4, KEV sowie separate FIRST-EPSS-Tageshistorien umgesetzt.
Alle 45 Aufträge, 140 Pflichtprüfungen und 75 ENR-Invarianten lokal abgenommen.
78 aktuelle Enricherfälle; insgesamt 1.131 unterschiedliche relevante Fälle einschließlich
Regression nachgewiesen. Migrationen 00021/00022 aktiv, neun eigene Dienste gesund.
Keine administrativen Änderungen, kein Matching und keine Finding-Erzeugung.
[Abnahme](phase-16-acceptance.md), [Status](phase-16-status.md), [Übergabe](phase-16-handover.md).

## Phase 17

Abgeschlossen: cve-matcher 0.17.0 und Migration 00023 aktiv, zehn eigene Dienste gesund; Details im [Phasenstatus](phase-17-status.md).

## Phase 18

Abgeschlossen: cve-findings und cve-api 0.18.0, Migration 00025 aktiv; elf eigene Dienste gesund.
Alle 45 Aufträge und 164 Kriterien sind in [Status](phase-18-status.md),
[Abnahme](phase-18-acceptance.md) und [Testmatrix](../testing/phase-18-test-matrix.md) nachgewiesen.

## Phase 19

Abgeschlossen am 09.11.2026: n8n Regular Mode, cve-notification/API 0.19.0 und Head 00027
aktiv; dreizehn eigene Dienste gesund. [Status](phase-19-status.md),
[Abnahme](phase-19-acceptance.md), [Übergabe](phase-19-handover.md).


## Phase 24

Release-/Deployment-/Recoveryoperatoren, isolierte Gesamtintegration und
konsolidierte Betriebs-/Bedienungsdokumentation:
[Status und formale Freigabegrenzen](phase-24-status.md),
[186 Abnahmekriterien](phase-24-acceptance.md), [Übergabe](phase-24-handover.md).
Die tatsächliche technische Abschlussentscheidung steht in
`.runtime/test-reports/phase-24-acceptance.json`; fehlende Gitidentität und
Produktivgenehmigung werden nicht als erfolgreich ausgegeben.
