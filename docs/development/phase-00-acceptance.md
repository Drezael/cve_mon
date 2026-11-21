# Phase-0-Abnahme T00.06.05

Stand: 05.11.2026. **Status: completed. Phase 0 ist als Spezifikationsphase abgeschlossen.**
Alle 33 Aufträge sind abgeschlossen; [Einzelstatus](phase-00-status.md).
Die anschließende [Phase-1-Auswirkungsprüfung](phase-01-impact.md) ist umgesetzt und lokal abgenommen.

## Ergebnis und Prüfstand

16 Komponenten, fünf Netze, elf Architektur-/Datenflussdiagramme, 19 ADRs,
22 spätere Architektur-Abnahmeszenarien und die 28 Kriterien A00.01–A00.28 sind dokumentiert.
Inventarvertrag v1 mit sechs Beispielen, OpenAPI 3.1.0 mit 87 Operationen,
logisches PostgreSQL-Modell, Rollen-/Grant-Matrix und Sicherheitsmodell sind konsistent verknüpft.
Keine produktiven Dienste, Tabellen, Migrationen oder Infrastrukturkonfigurationen implementiert.

**117 Pytest-Fälle bestehen**, davon 66 neue Vertrags-/Regressionsfälle zusätzlich zu den
51 ursprünglichen Phase-1-Tests. Ruff, Formatprüfung, striktes Mypy (10 Dateien), YAML/JSON,
Draft2020-12 mit aktiver UUID-/RFC3339-Prüfung, OpenAPI-Semantik, Referenzen, Beispielerwartungen,
Sicherheitsinvarianten und lokales Secret-Scanning bestehen.

Die 19 zusätzlichen Abnahmeschritte wurden in einer frischen Projektkopie mit Leerzeichen
im Pfad ausgeführt. Erster Bootstrap aus fremdem Arbeitsverzeichnis, Wiederholung ohne
Verlust von Markierungsdatei/Interpreter und Installation des aktualisierten Hash-Locks sind erfolgreich.
Ein absichtlicher Pytest-Fehler lieferte 1 failed, 117 passed und stoppt den Make-Lauf.
Alle Fehlerexperimente fanden in temporären Kopien statt, nicht an den Projektverträgen.

| Prüfung | Exit-Code | Ergebnis |
|---|---|---|
| Frisches Git-Repository | 0 | Erfolgreich |
| Neue .venv mit Hash-Installation | 0 | Erfolgreich |
| Wiederholtes Setup mit erhaltenem Interpreter/Marker | 0 | Erfolgreich |
| make help | 0 | Erfolgreich |
| make format | 0 | Erfolgreich |
| make check in frischer Umgebung | 0 | Erfolgreich |
| pip check | 0 | Erfolgreich |
| Fehlende pyproject.toml erkannt | 2 | Erwartet fehlgeschlagen |
| Ungültiges YAML erkannt | 2 | Erwartet fehlgeschlagen |
| Ungültiges JSON erkannt | 2 | Erwartet fehlgeschlagen |
| Ungültige Schema-Definition erkannt | 2 | Erwartet fehlgeschlagen |
| Lintfehler stoppt make check | 2 | Erwartet fehlgeschlagen |
| Fehlschlagender Pytest stoppt make check | 2 | Erwartet fehlgeschlagen |
| Neues synthetisches Secret stoppt make check | 2 | Erwartet fehlgeschlagen |
| Vollständiger Check nach Bereinigung | 0 | Erfolgreich |
| mTLS ODER Token statt UND wird abgelehnt | 2 | Erwartet fehlgeschlagen |
| Semantisch ungültige OpenAPI wird abgelehnt | 2 | Erwartet fehlgeschlagen |
| Beschädigtes positives Inventarbeispiel wird abgelehnt | 2 | Erwartet fehlgeschlagen |
| Verträge nach Bereinigung gültig | 0 | Erfolgreich |


## Abnahmematrix

| Kriterium | Prüfbereich | Nachweis / Ergebnis |
|---|---|---|
| A00.01 | Komponenten | 16 Dienste samt externen Quellen, Daten, Fehlern und Health in components.md |
| A00.02 | Zuständigkeiten | Verantwortungsmatrix und rollenbezogene DB-Matrix; Admin-Writes getrennt |
| A00.03 | Datenflüsse | 11 Mermaid-Diagramme in overview.md/data-flow.md |
| A00.04 | Netzwerke | 5 Netze, alle Containerzuordnungen und feste erlaubte Wege; Policy-Negativtests |
| A00.05 | Ingress | Dedizierter mTLS-Host gegenüber gleichoriginigen Sitzungspfaden |
| A00.06 | Egress | Host-/Port-/Client-Allowlist, IPv4/IPv6 und DNS-Rebinding spezifiziert |
| A00.07 | Postfix | Fester server-first TCP-Tunnel, STARTTLS zur externen Identität, persistente Queue |
| A00.08 | Statuspage | Feste direkte HTTP/DB/SMTP-Checks, neue Prüfung je Aufruf, kein Dockerzugriff |
| A00.09 | Inventarschema | Draft2020-12-Schema gültig; geschlossen auf jeder Objektebene |
| A00.10 | Serveridentität | UUID-Formate und Registrierungspflicht; keine Hostnamenidentität |
| A00.11 | Inventarbeispiele | 3 positive und 3 negative Beispiele mit geprüftem konkretem Ablehnungsgrund |
| A00.12 | Idempotenz | Globale inventory_id, kanonischer Hash, Cross-Channel-Receipts und Unique-Regeln |
| A00.13 | API-Verträge | POST inventories: mTLS UND Token UND Scope/Objektbindung |
| A00.14 | Dashboard-Upload | POST dashboard/inventories/upload: Sitzung UND CSRF, gleicher Fachvertrag |
| A00.15 | Gruppenverwaltung | Nur menschlicher /dashboard/admin-Kontext und dashboard_admin-Schreibrolle |
| A00.16 | Sortierung | Eigene versionierte dashboard-Sortieraggregate, keine Uploadfelder |
| A00.17 | PostgreSQL | Zwei PostgreSQL-Datenbanken, acht Fachschemas und vollständige logische Tabellendefinitionen |
| A00.18 | Datenbankrechte | Inventory-Rollen ohne organisatorische Writes, Negativprüfung der Rollenzuordnung |
| A00.19 | Benutzerverwaltung | Argon2id, TOTP, Sitzungswiderruf, Kontolebenszyklus und letzter Admin definiert |
| A00.20 | Hintergrundjobs | PostgreSQL-Jobs mit Lease/Fencing und Transactional Outbox |
| A00.21 | Offlinefähigkeit | Lokale Suche/Inventare/Benutzer/Matching ohne externen Quellenzwang |
| A00.22 | Bedrohungsmodell | 16 Bedrohungsfälle mit Maßnahmen, Zuständigkeit, Restrisiko und Prüfnachweis |
| A00.23 | ADRs | 19 accepted-ADRs, vollständige Abschnitte und geprüfte lokale Dateiverweise |
| A00.24 | Konsistenz | 28-zeilige Traceability-Matrix; Schema/API/Rechte/Netze gemeinsam geprüft |
| A00.25 | Testszenarien | 22 detaillierte SC00-Szenarien; Runtime-Nachweise ausdrücklich später |
| A00.26 | Dokumentation | Pflichtmanifest vollständig; alle 33 Aufgaben dokumentiert |
| A00.27 | Abgrenzung | Keine Compose-Dateien, Dockerfiles, SQL-Migrationen oder Python-Fachdienste erzeugt |
| A00.28 | Übergabe | Rückwirkende Übergabe an Phase 1 und erfolgreich integrierte Vertragsprüfungen |


## Neue und geänderte Dateien

Gegenüber dem Bestand zu Beginn dieses Auftrags: 64 neue und 24 geänderte Dateien.

```text
contracts/api/openapi.yaml
contracts/inventory/examples/invalid-group-assignment.json
contracts/inventory/examples/invalid-server-id.json
contracts/inventory/examples/invalid-timestamp.json
contracts/inventory/examples/valid-partial.json
contracts/inventory/examples/valid-ubuntu.json
contracts/inventory/examples/valid-with-containers.json
contracts/inventory/inventory-v1.schema.json
contracts/inventory/rejection-cases.md
contracts/phase-00-manifest.json
contracts/security/service-access-v1.json
docs/api/authentication-boundaries.md
docs/api/conventions.md
docs/architecture/availability-and-offline.md
docs/architecture/components.md
docs/architecture/current-state.md
docs/architecture/data-flow.md
docs/architecture/decisions/ADR-0001-postgresql-only.md
docs/architecture/decisions/ADR-0002-n8n-orchestration.md
docs/architecture/decisions/ADR-0003-postgres-jobs.md
docs/architecture/decisions/ADR-0004-transactional-outbox.md
docs/architecture/decisions/ADR-0005-docker-compose.md
docs/architecture/decisions/ADR-0006-nginx-ingress.md
docs/architecture/decisions/ADR-0007-envoy-egress.md
docs/architecture/decisions/ADR-0008-postfix-queue.md
docs/architecture/decisions/ADR-0009-manual-ansible.md
docs/architecture/decisions/ADR-0010-technical-upload.md
docs/architecture/decisions/ADR-0011-dashboard-upload.md
docs/architecture/decisions/ADR-0012-shared-inventory.md
docs/architecture/decisions/ADR-0013-inventory-isolation.md
docs/architecture/decisions/ADR-0014-dashboard-groups.md
docs/architecture/decisions/ADR-0015-dashboard-order.md
docs/architecture/decisions/ADR-0016-local-users.md
docs/architecture/decisions/ADR-0017-totp-admins.md
docs/architecture/decisions/ADR-0018-live-status.md
docs/architecture/decisions/ADR-0019-offline-analysis.md
docs/architecture/decisions/README.md
docs/architecture/egress.md
docs/architecture/ingress.md
docs/architecture/internal-trust.md
docs/architecture/networks.md
docs/architecture/open-points.md
docs/architecture/overview.md
docs/architecture/responsibilities.md
docs/architecture/statuspage.md
docs/database/access-matrix.md
docs/database/automation-and-audit.md
docs/database/cve-and-findings.md
docs/database/inventory.md
docs/database/overview.md
docs/database/security.md
docs/database/server-and-groups.md
docs/development/phase-00-acceptance.md
docs/development/phase-00-handover.md
docs/development/phase-00-plan.md
docs/development/phase-00-status.md
docs/development/phase-00-traceability.md
docs/development/phase-01-impact.md
docs/security/authentication.md
docs/security/authorization.md
docs/security/threat-model.md
docs/testing/architecture-acceptance-scenarios.md
scripts/validate_contracts.py
tests/unit/test_contracts.py
```

Geänderte zu Beginn vorhandene Dateien:

```text
README.md
contracts/api/README.md
contracts/events/README.md
contracts/inventory/README.md
contracts/security/README.md
database/migrations/README.md
database/schemas/README.md
docs/architecture/README.md
docs/database/README.md
docs/development/developer-setup.md
docs/development/development-status.md
docs/development/phase-01-acceptance.md
docs/development/phase-01-plan.md
docs/security/README.md
docs/statuspage/README.md
docs/testing/README.md
requirements/dev.in
requirements/dev.txt
scripts/validate_repository.py
services/README.md
services/dashboard/administration/README.md
services/inventory/README.md
services/uploads/dashboard/README.md
services/uploads/technical/README.md
```

Die vom Nutzer bereitgestellten Originale dev_docs/phase_00.md und dev_docs/phase_01.md
sind anhand ihrer vor Bearbeitung erfassten SHA-256-Werte unverändert. Die Secret-Baseline
ist unverändert und enthält keine akzeptierten Funde. Keine echten Zugangsdaten eingefügt.
Keine Commits, kein Push, keine Container gestartet und keine externen Ansible-Dateien geändert.

## Grenzen, offene Punkte und Freigabe

Diese Abnahme bestätigt Spezifikationen und Entwicklungsprüfungen, keine laufende Fachanwendung.
PostgreSQL-Grants/FKs/RLS, Race Conditions, reale TLS-/SMTP-/Netzwerkregeln und Dienstverfügbarkeit
wurden nicht an Produktivkomponenten getestet. Diese Nachweise sind in den 22 Szenarien und
[OP00.01–11](../architecture/open-points.md) den späteren Implementierungsphasen zugeordnet.

Gesamtkonzept 3.12 und Entwicklungsplan 1.2 fehlen als separate Originale; die verbindlichen
Vorgaben aus den nachgereichten Phasenkonzepten wurden übernommen. Ohne Gesamtplan werden keine
numerischen Zuordnungen unbekannter Folgephasen erfunden. Vor Folgeimplementierung Originale
abgleichen und konkretes Phase-2-Konzept bereitstellen. Kein erkannter offener Widerspruch in
den verfügbaren Architekturvorgaben. Gehostete GitHub-CI ist mangels Remote/Veröffentlichung
nicht ausgeführt; lokaler CI-Befehl ist geprüft.

Phase 0 ist zur Nutzung als verbindliche Entwicklungsgrundlage freigegeben. Die bereits
vorhandene Phase 1 erhält diese Ergebnisse rückwirkend und validiert sie automatisiert.
Phase 2 wurde nicht begonnen.

## Nachfolgende Phase 2

Die obige Abnahme dokumentiert den Phase-0-Stand. Phase 2 erweitert die 19 ursprünglichen
ADRs um ADR-0020 und präzisiert den Portvertrag auf HTTP-Weiterleitung/80 plus HTTPS/443.
Siehe [Phase-2-Abnahme](phase-02-acceptance.md). Die ursprünglichen Phasenkonzepte bleiben unverändert.
