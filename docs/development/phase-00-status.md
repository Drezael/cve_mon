# Fortschritt Phase 0

Stand: 05.11.2026. **Phase 0: completed — alle 33 Spezifikationsaufträge abgeschlossen.**
Keine Produktivdienste implementiert. Die maschinellen Prüfungen sind in der vorhandenen
Phase-1-Umgebung ausgeführt. Runtime-/Integrationsnachweise folgen in den benannten Fachphasen;
[offene technische Punkte](../architecture/open-points.md) bleiben ausdrücklich ausgewiesen.

| Aufgabe | Titel | Status | Voraussetzungen | Neue Dokumente | Geänderte bestehende Dokumente | Prüfergebnis | Abschluss |
|---|---|---|---|---|---|---|---|
| T00.01.01 | Projektstand analysieren | completed | Vorhandene Phase 1 und Originalkonzept | docs/architecture/current-state.md | — | Bestand/Git/Phasenunterlagen geprüft; keine Produktivdatei geändert | 05.11.2026 |
| T00.01.02 | Komponentenkatalog erstellen | completed | T00.01.01 | docs/architecture/components.md, contracts/security/service-access-v1.json | — | 16 Komponenten mit Architekturvertrag abgeglichen | 05.11.2026 |
| T00.01.03 | Verantwortlichkeiten definieren | completed | T00.01.02 | docs/architecture/responsibilities.md | — | Schreibhoheit mit DB-/API-Verträgen konsistent | 05.11.2026 |
| T00.01.04 | Gesamtarchitektur und Datenflüsse | completed | T00.01.03 | docs/architecture/overview.md, docs/architecture/data-flow.md | — | 11 Mermaid-Diagramme gegen Zuständigkeitsmatrix geprüft | 05.11.2026 |
| T00.01.05 | Abhängigkeiten und Ausfälle | completed | T00.01.04 | docs/architecture/availability-and-offline.md | — | 11 Ausfallszenarien und Offlinegrenzen spezifiziert | 05.11.2026 |
| T00.02.01 | Docker-Netzwerkkonzept | completed | T00.01.05 | docs/architecture/networks.md | — | 5 Netze, 16 Zuordnungen und Ingress-/Egress-Regeln geprüft | 05.11.2026 |
| T00.02.02 | Nginx-Ingress-Konzept | completed | T00.02.01 | docs/architecture/ingress.md | — | mTLS-/Sitzungsgrenzen und geschützte Weiterleitung spezifiziert | 05.11.2026 |
| T00.02.03 | Envoy- und SMTP-Egress | completed | T00.02.02 | docs/architecture/egress.md | — | Quellen-Allowlist, SMTP server-first, externe TLS-Identität und Queue geprüft | 05.11.2026 |
| T00.02.04 | Interne Vertrauensgrenzen | completed | T00.02.03 | docs/architecture/internal-trust.md | — | Dienstidentitäten, Minimalrollen und Pooltrennung konsistent | 05.11.2026 |
| T00.02.05 | Statuspage-Architektur | completed | T00.02.04 | docs/architecture/statuspage.md | — | Alle Dienste mit Direktchecks, acht Zuständen und festen Prüfgrenzen erfasst | 05.11.2026 |
| T00.02.06 | Bedrohungsmodell | completed | T00.02.05 | docs/security/threat-model.md | — | 16 Bedrohungsfälle mit Schutz, Restrisiko und Nachweis beschrieben | 05.11.2026 |
| T00.03.01 | Inventarumfang und Identität | completed | T00.02.06 | — | contracts/inventory/README.md | Pflichtfelder/UUID/keine Steuerfelder spezifiziert | 05.11.2026 |
| T00.03.02 | Versioniertes Inventar-JSON-Schema | completed | T00.03.01 | contracts/inventory/inventory-v1.schema.json | — | Draft2020-12, UUID/RFC3339 und negative Verschachtelungsfälle maschinell geprüft | 05.11.2026 |
| T00.03.03 | Vollständigkeits- und Softwaremodell | completed | T00.03.02 | — | contracts/inventory/README.md | complete/partial/failed/not_collected und echte Leere maschinell unterschieden | 05.11.2026 |
| T00.03.04 | Beispielinventare | completed | T00.03.03 | contracts/inventory/examples/valid-ubuntu.json, contracts/inventory/examples/valid-partial.json, contracts/inventory/examples/valid-with-containers.json, contracts/inventory/examples/invalid-group-assignment.json, contracts/inventory/examples/invalid-server-id.json, contracts/inventory/examples/invalid-timestamp.json | — | Drei positive/drei negative Beispiele einschließlich Ablehnungsgrund bestanden | 05.11.2026 |
| T00.03.05 | Idempotenz und Historisierung | completed | T00.03.04 | contracts/inventory/rejection-cases.md | — | Kanalübergreifende Idempotenz und Historisierungsfälle spezifiziert | 05.11.2026 |
| T00.04.01 | Allgemeine API-Konventionen | completed | T00.03.05 | docs/api/conventions.md | contracts/api/README.md | Konventionen/Fehler/ETag/Pagination gegen OpenAPI geprüft | 05.11.2026 |
| T00.04.02 | Technischen Inventar-Upload definieren | completed | T00.04.01 | contracts/api/openapi.yaml, docs/api/authentication-boundaries.md | — | mTLS UND Token, Scope und gemeinsamer Inventarvertrag maschinell geprüft | 05.11.2026 |
| T00.04.03 | Dashboard-Datei-Upload definieren | completed | T00.04.02 | contracts/api/openapi.yaml, docs/api/authentication-boundaries.md | — | Sitzung UND CSRF, Multipart/Zielserver und Herkunft geprüft | 05.11.2026 |
| T00.04.04 | Server-, Gruppen- und Sortier-API | completed | T00.04.03 | contracts/api/openapi.yaml, docs/database/server-and-groups.md | — | Admin-Routen, Mitgliedschaft/Primärgruppe/Sortierung und If-Match geprüft | 05.11.2026 |
| T00.04.05 | Benutzer- und Authentifizierungs-API | completed | T00.04.04 | contracts/api/openapi.yaml, docs/security/authentication.md | — | Kontolebenszyklus, Rollen/MFA/Sitzungen und letzter Administrator konsistent | 05.11.2026 |
| T00.04.06 | Sicherheits-APIs und Statuspage | completed | T00.04.05 | contracts/api/openapi.yaml, docs/api/authentication-boundaries.md | — | Fach-APIs und feste no-store-Statusabfrage semantisch geprüft | 05.11.2026 |
| T00.05.01 | PostgreSQL-Schemas und Beziehungen | completed | T00.04.06 | docs/database/overview.md | — | Zwei PostgreSQL-Datenbanken, acht Fachschemas und ER-Modell geprüft | 05.11.2026 |
| T00.05.02 | Server- und Gruppendatenmodell | completed | T00.05.01 | docs/database/server-and-groups.md | — | FK-/Versions-/Archivierungs-/Sortierregeln logisch geprüft | 05.11.2026 |
| T00.05.03 | Inventar- und Softwaredatenmodell | completed | T00.05.02 | docs/database/inventory.md | — | Historisierung, Normalisierung, Originale und Isolation logisch geprüft | 05.11.2026 |
| T00.05.04 | CVE-, Matching- und Finding-Modell | completed | T00.05.03 | docs/database/cve-and-findings.md | — | CVE-Provenienz, Mehrfachversionen, Backports, Risiko und Findings logisch geprüft | 05.11.2026 |
| T00.05.05 | Benutzer- und Sicherheitsdatenmodell | completed | T00.05.04 | docs/database/security.md | — | Alle 14 geforderten plus drei technische Sicherheitstabellen beschrieben | 05.11.2026 |
| T00.05.06 | Jobs, Audit und Datenbankrechte | completed | T00.05.05 | docs/database/automation-and-audit.md, docs/database/access-matrix.md, docs/security/authorization.md, docs/security/authentication.md | — | Jobs/Fencing/Outbox/Audit und explizite Rechte logisch geprüft | 05.11.2026 |
| T00.06.01 | ADR-System einrichten | completed | T00.05.06 | docs/architecture/decisions/README.md | — | ADR-Verfahren mit allen vier zulässigen Statuswerten dokumentiert | 05.11.2026 |
| T00.06.02 | Architekturentscheidungen erstellen | completed | T00.06.01 | docs/architecture/decisions/ADR-0001-postgresql-only.md, docs/architecture/decisions/ADR-0002-n8n-orchestration.md, docs/architecture/decisions/ADR-0003-postgres-jobs.md, docs/architecture/decisions/ADR-0004-transactional-outbox.md, docs/architecture/decisions/ADR-0005-docker-compose.md, docs/architecture/decisions/ADR-0006-nginx-ingress.md, docs/architecture/decisions/ADR-0007-envoy-egress.md, docs/architecture/decisions/ADR-0008-postfix-queue.md, docs/architecture/decisions/ADR-0009-manual-ansible.md, docs/architecture/decisions/ADR-0010-technical-upload.md, docs/architecture/decisions/ADR-0011-dashboard-upload.md, docs/architecture/decisions/ADR-0012-shared-inventory.md, docs/architecture/decisions/ADR-0013-inventory-isolation.md, docs/architecture/decisions/ADR-0014-dashboard-groups.md, docs/architecture/decisions/ADR-0015-dashboard-order.md, docs/architecture/decisions/ADR-0016-local-users.md, docs/architecture/decisions/ADR-0017-totp-admins.md, docs/architecture/decisions/ADR-0018-live-status.md, docs/architecture/decisions/ADR-0019-offline-analysis.md | — | 19 getrennte accepted-ADRs mit erforderlichen Abschnitten und Referenzen | 05.11.2026 |
| T00.06.03 | Konsistenz und Rückverfolgbarkeit | completed | T00.06.02 | docs/development/phase-00-traceability.md | — | 28 Rückverfolgbarkeitszeilen und lokale Verweise geprüft | 05.11.2026 |
| T00.06.04 | Architektur-Abnahmeszenarien | completed | T00.06.03 | docs/testing/architecture-acceptance-scenarios.md | — | 22 Szenarien mit API-/DB-Wirkung und verbotenen Nebenwirkungen beschrieben | 05.11.2026 |
| T00.06.05 | Phase-0-Abnahme und Übergabe | completed | T00.06.04 | docs/development/phase-00-plan.md, docs/development/phase-00-status.md, docs/development/phase-00-acceptance.md, docs/development/phase-00-handover.md | — | Gesamtabnahme/Übergabe und korrigierte Phase-1-Prüfungen erfolgreich | 05.11.2026 |

## Offene Probleme und Einschränkungen

Keine erkannten ungelösten Widersprüche der verfügbaren verbindlichen Vorgaben.
OP00.01–11 dokumentieren fehlende separate Originalgrundlagen und spätere technische Nachweise,
keine als ausgeführt behaupteten Runtime-Tests. Gesamtkonzept 3.12, Entwicklungsplan 1.2,
konkretes Phase-2-Konzept und gehosteter CI-Lauf stehen weiterhin aus.
Die Originalkonzepte wurden nicht geändert. Kein Commit, Push oder Deployment.
