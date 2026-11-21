# Übergabe an Phase 11

Verwaltungsbackend: stabile registrierte Server-UUIDs, explizite Stammdaten, aktive/archivierte
Lebenszyklen, Mehrfachmitgliedschaften mit verpflichtender Primärgruppe und drei persistente
Sortierkontexte. Native Rechte/FKs/Deferred-Guards und Versionsbedingungen bleiben verbindlich.

Phase 11 nimmt erst technische Inventare an. Technische mTLS/Bearer/Serverregistrierung und
inventory:submit bleiben getrennt von Browsercookie/CSRF/inventory:upload:dashboard plus
Server-ACL. Archivierte und unbekannte Server ablehnen. Keine automatische Registrierung,
Gruppierung, Primärgruppenwahl oder Sortieränderung durch irgendeinen Uploadweg. Verwende
bestehendes Inventarschema und rekursive Schutzprüfungen, keine Aliasumgehung.

Dashboard nutzt die vier OpenAPI-Verträge und aktuellen ETags; kritische Writes mit neuer
Einmal-Reauth. Bei Konflikten neue Daten lesen und bewusste Entscheidung einholen. Keine
Clientrollen oder cached Principals. Gruppen sind keine ACL-Vererbungsquelle. Bei neuen
Fachservices Service-Level-Validierung und transaktionale Audit/Outbox übernehmen.

Die administrative Schreibidentität dashboard_admin bleibt in eigenem Pool; Ingestion/
Processor/Matcher erhalten keine Verwaltungswrites. Technische Identität später kontrolliert
mit einer existierenden Server-UUID verbinden; die Legacy-Hostidentität kann derzeit NULL sein.
UI Phase 20–21, Benachrichtigungen Phase 19, große Bestände/Lockskalierung Phase 23.
[Abnahme](phase-10-acceptance.md), [Datenmodell](../database/administrative-inventory-model.md).
