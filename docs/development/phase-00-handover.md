# Rückwirkende Übergabe Phase 0 → Phase 1

Stand: 05.11.2026. Status: completed. Phase 0 ist als Spezifikation freigegeben;
Phase 1 war bereits vorhanden und ist nach Abgleich korrigiert und erneut geprüft.

## Verbindliche Artefakte

- docs/architecture: Komponenten, Datenhoheit, Datenflüsse, Ausfall-/Netz-/Ingress-/Egress-/Statusmodell und 19 ADRs.
- contracts/inventory: Draft2020-12-Schema v1, sechs Beispiele und Annahme-/Idempotenzregeln.
- contracts/api/openapi.yaml und docs/api: OpenAPI 3.1.0, Konventionen und Identitätsgrenzen.
- docs/database und docs/security: logisches Modell, Grant-Matrix, Authentifizierung, Autorisierung und Bedrohungen.
- contracts/security/service-access-v1.json: überprüfbarer Architekturvertrag, keine Laufzeitkonfiguration.
- contracts/phase-00-manifest.json: verpflichtende Dateien und explizite Beispielerwartungen.
- docs/testing/architecture-acceptance-scenarios.md und Phase-0-Traceability/Status/Abnahme.

Normative Payload-/Pfaddefinitionen stehen in Schema/OpenAPI; dokumentierte Fachregeln,
Datenhoheit und Sicherheitsgrenzen gelten zusätzlich. Widersprüche müssen vor Implementierung
aufgelöst werden, niemals durch stilles Überschreiben. Bestehende Dokumente und Originalkonzepte erhalten.

## Technische Konventionen und Struktur

Python 3.12, englische technische IDs, deutsche Erläuterungen, UUIDs, RFC3339, unveränderte
Softwareversionen, API /api/v1. Zwei Uploadwege, dieselbe Inventarverarbeitung, kein Upload-
Schreibrecht auf Stammdaten/Gruppen/Sortierung. PostgreSQL ist einziges Datenbanksystem
mit isolierten Datenbanken n8n und cve_monitoring. n8n regulär, Fachjobs und Outbox persistent.

docs/api und docs/architecture/decisions sowie die konkreten Vertrags-/Beispieldateien ergänzen
die vorhandene Phase-1-Struktur. Vorbereitete Upload-/Administrationsverzeichnisse sind keine
zusätzlichen Container; ihre ausführenden Kontexte gehören zu cve-api beziehungsweise cve-inventory.

## In Phase 1 nachgeholte Prüfungen

Bereits vorhanden waren Ruff/Mypy/Pytest/Yamllint/jsonschema/detect-secrets.
Ergänzt: openapi-spec-validator 0.9.0 und rfc3339-validator 0.1.4 mit vollständigem Hash-Lock.
make validate prüft jetzt OpenAPI mit lokalen Referenzen, Inventarbeispiele samt gezielter
Ablehnung, aktive Formate, Sicherheits-/Netz-/Rolleninvarianten und lokale Dokumentverweise.
make check und der bestehende CI-Workflow führen dies automatisch mit aus.
117 Tests und frische Installation mit wiederholtem Setup sind erfolgreich.
Keine mangels Werkzeugen aufgeschobene Phase-0-Vertragsprüfung bleibt offen.

## Spätere Nachweise

Tatsächliche Datenbank-, TLS-, Netzwerk-, SMTP-, n8n-, Matching- und Benutzerfunktionen
sind noch nicht implementiert/getestet. 22 Szenarien und OP00.01–11 bilden den verbindlichen
Prüfauftrag für die jeweiligen Folgephasen. Gehostete CI bleibt bis zur Veröffentlichung offen.
Separate Originalgrundlagen und konkretes Phase-2-Konzept vor Folgeimplementierung abgleichen.
[Abnahme](phase-00-acceptance.md), [Phase-1-Korrekturen](phase-01-impact.md).
