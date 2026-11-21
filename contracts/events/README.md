# Transactional-Outbox-Vertrag v1

Ereignisse werden mit Fachänderungen atomar in PostgreSQL persistiert und durch
cve-event-dispatcher mindestens einmal an n8n geliefert. Kein zusätzlicher Broker.
Der OpenAPI-Typ OutboxEvent enthält event_id, event_type, source, entity_id,
occurred_at und idempotency_key; Korrelations-ID und Zustellmetadaten liegen im DB-Modell.

| Ereignis | Produzent | Erlaubte Folge |
|---|---|---|
| inventory.received | cve-api / api_ingest | Bereits atomar angelegten inventory.process-Job beobachten, nicht doppelt erzeugen |
| inventory.processed | cve-inventory | matching.run |
| cve.updated | cve-importer oder cve-enricher mit Quellenreferenz | Betroffene Server lokal neu auswerten |
| matching.completed | cve-matcher | findings.reconcile |
| finding.changed | cve-findings | report.generate beziehungsweise notification.send gemäß Regel |
| report.ready | cve-reporter | Benachrichtigung im berechtigten Empfängerkreis |
| notification.requested | Autorisierter Fachkontext | Idempotente cve-notification-Verarbeitung |

Event-ID plus Consumer/Jobtyp deduplizieren. Quellenidentität ist aus dem Fachschreiber gebunden,
nicht frei behauptet. Keine Gruppe, Primärgruppe, Sortieraktion oder ausführbare URL aus
Inventarereignissen ableiten. Details: [Jobs/Outbox](../../docs/database/automation-and-audit.md).

Phase 3 konkretisiert die Outboxtypen gemäß [physischem Modell](../../docs/database/automation-and-audit.md)
und OpenAPI 1.1.0: inventory.accepted sowie getrennte cve.imported/cve.enriched.
Die Zustelllogik bleibt Aufgabe der nachfolgenden Worker-/n8n-Phasen.

Phase 7 ergänzt den ausführbaren [Event-Envelope-Vertrag](event-envelope-v1.schema.json),
strikte Payload-/Quellvalidierung und [zustellende Outbox](../../docs/architecture/transactional-outbox.md).
Produktive n8n-Ziele bleiben bis Phase 19 geschlossen.

Phase 15: [cve-import-v1](cve-import-v1.schema.json) beschreibt die Metadaten für
`cve.source.new/changed/withdrawn/removed/completed/partial/failed`. Rohpayloads sind ausgeschlossen.

Phase 16: [Enrichment v1](cve-enrichment-v1.schema.json) beschreibt granulare
Metadatenereignisse; EPSS-Datasets werden getrennt signalisiert.
