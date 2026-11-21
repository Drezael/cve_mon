# Konsistenz und Rückverfolgbarkeit T00.06.03

Jeder Prüfbereich verweist auf ADRs, verantwortliche Komponenten, Schnittstellen,
Datenmodell, spätere Implementierungsphase und konkrete SC00-Szenarien.
ADRs liegen in docs/architecture/decisions, Szenarien in docs/testing.
Ein fehlender separater Gesamtplan erlaubt keine erfundenen Folgephasennummern;
OP00.01 hält den erforderlichen numerischen Abgleich fest.

| Anforderung | Entscheidung (ADR) | Komponente | Schnittstelle / Dokument | Datenmodell | Folgephase | Abnahmeszenario SC00 |
|---|---|---|---|---|---|---|
| A00.01: Komponenten | 0005 | alle 16 Dienste | Komponentenkatalog | Alle Modellbereiche | Phase 2 und Fachdienstphasen | 19,20 |
| A00.02: Zuständigkeiten | 0013 | API/Inventory/Matcher | Upload/Admin | Grant-Matrix | API/Datenbank | 10,13,14 |
| A00.03: Datenflüsse | 0004 | alle Fachschreiber | Outbox/Job-APIs | automation | Orchestrierung | 14,15 |
| A00.04: Netzwerke | 0005 | Nginx/Envoy/DB | Kommunikations-ACL | Service-Access-Vertrag | Phase 2 | 02,20 |
| A00.05: Ingress | 0006 | Nginx/API | Beide Upload-Endpunkte | Receipts | Phase 2/API | 01,04 |
| A00.06: Egress | 0007 | Envoy/Importer/Enricher | Forward-Proxy/CONNECT | Quellenstände | Egress/Import | 17 |
| A00.07: Postfix | 0008 | Postfix/Envoy/Notification | SMTP-TCP/STARTTLS | notification_deliveries | SMTP | 18 |
| A00.08: Statuspage | 0018 | Statusdienst | Deployment-Status | SELECT 1 | Statuspage | 19,20 |
| A00.09: Inventarschema | 0012 | API/Inventory | Inventory v1 | snapshots | Phase 1/Inventar | 01,09 |
| A00.10: Serveridentität | 0010 | API/Inventory | server_id | servers/snapshots | Inventar | 07,08 |
| A00.11: Inventarbeispiele | 0012 | API/Inventory | Sechs JSON-Beispiele | snapshots | Phase 1 | 01,04,09 |
| A00.12: Idempotenz | 0003 | API/Inventory | Annahme-/Duplikatvertrag | UNIQUE inventory_id | API/Datenbank | 01,04 |
| A00.13: API-Verträge | 0010 | Nginx/API | POST inventories | upload_receipts | Ingress/API | 01,02,03 |
| A00.14: Dashboard-Upload | 0011 | Dashboard/API | POST dashboard/inventories/upload | upload_receipts | Dashboard | 04,05,06 |
| A00.15: Gruppenverwaltung | 0014 | API-Verwaltung | dashboard/admin | Gruppen/Mitgliedschaften | Verwaltung | 11,13,14 |
| A00.16: Sortierung | 0015 | API-Verwaltung | order PUT mit If-Match | dashboard.order_versions | Dashboard | 12 |
| A00.17: PostgreSQL | 0001 | alle DB-Clients | Modell/FKs | Alle acht Fachschemas | Datenbank | 10,11,22 |
| A00.18: Datenbankrechte | 0013 | Inventory Processor | DB-Rollengrenze | Verbotene Admin-Writes | Datenbank | 10,14 |
| A00.19: Benutzerverwaltung | 0016,0017 | API/Sicherheit | Login/MFA/Admin | security | Authentifizierung | 21,22 |
| A00.20: Hintergrundjobs | 0003,0004 | Worker/Dispatcher/n8n | Interne Job-/Event-APIs | automation | Jobs/n8n | 14,15 |
| A00.21: Offlinefähigkeit | 0019 | Importer/Matcher/API | Lokale Suche/Matching | Lokale Revisionen | Matching/Betrieb | 17 |
| A00.22: Bedrohungsmodell | 0007,0013 | alle Vertrauensgrenzen | Threat Model | Sicherheits-/Fachmodelle | Sicherheit | 02,06,08,09 |
| A00.23: ADRs | 0001–0019 | alle Komponenten | ADRs | Verlinkte Modelle | Alle Folgephasen | 01–22 |
| A00.24: Konsistenz | 0013 | API/Inventory/Verwaltung | Vertrags-/Referenzprüfung | Grant-/Netzmatrix | Phase 1 | 09,10,13 |
| A00.25: Testszenarien | 0018 | alle Szenarien | SC00-01 bis SC00-22 | Erwartete DB-Wirkungen | Fachliche Folgephasen | 01–22 |
| A00.26: Dokumentation | 0005 | Dokumentation | Phase-0-Manifest | Keine Produktivtabellen | Phase 0/1 | 01–22 |
| A00.27: Abgrenzung | 0005 | Repository | Keine Laufzeitimplementierung | Keine Migrationen | Phase 0/1 | 20 |
| A00.28: Übergabe | 0012 | Phase-1-Werkzeuge | make validate/check | Schemaprüfung und Beispiele | Phase 1 | 01,04,09 |

## Konsistenzprüfung

- Komponentennamen/Netze/Rollen gegen service-access-v1.json und DB-Matrix abgeglichen.
- Beide Uploads referenzieren dasselbe Inventory-Schema; Herkunft ist kein Clientfeld.
- Technischer Upload benötigt mTLS UND Token, Dashboard-Write Sitzung UND CSRF.
- Alle Admin-Endpunkte bleiben im menschlichen Dashboard-Kontext; keine technische Tokenalternative.
- Gruppen-/Sortierhoheit ausschließlich dashboard_admin, keine Inventory-/Matching-/n8n-Schreibrechte.
- UUID, Originalversionen, Teilinventare und Snapshot-Historisierung sind in Schema/API/Modell konsistent.
- Statuspage nutzt feste aktuelle Direktchecks und hat dieselben Zustände im API-Vertrag.
- Offlinefähigkeit, n8n-Regulärmodus, Jobs/Outbox und SMTP-Queue durchgängig berücksichtigt.

Maschinelle Vertragsprüfungen und gezielte Negativtests laufen in Phase 1 mit make validate/check.
Versionsabhängige Runtime-Nachweise sind [offene Folgepunkte](../architecture/open-points.md),
keine behaupteten erfolgreichen Container-/DB-Tests. Keine erkannten offenen Widersprüche der
verfügbaren verbindlichen Architekturvorgaben; separate Originalgrundlagen bleiben abzugleichen.
