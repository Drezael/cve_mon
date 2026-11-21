# Administratives Inventory-Datenmodell

Additive Alembic-Revision 00016_server_administration nach 00015. Alle Daten bleiben in den
vorhandenen inventory-/dashboard-Schemas. Keine Kopie der Server-/Gruppentabellen.

| Tabelle | Ergänzung / Verwendung |
|---|---|
| inventory.servers | exposure, globale display_order, created_by/updated_by, optionale Legacy-Identität als Paar |
| inventory.server_groups | Archivzeit, created_by/updated_by; vorhandene Namen/Position/Version |
| inventory.server_group_memberships | vorhandener PK, display_order, actor_id; native Primär-/Archiv-Guards |
| dashboard.order_versions | global servers und getrennte group:<UUID>-Revisionen |
| inventory.administration_requests | Actor + request_id → Digest/Server für idempotente Registrierung |

Vorhandene FK primary_group_is_membership und Versions-/Identitätstrigger bleiben bestehen.
Neue Deferred-Guards prüfen Primärgruppe genau bei vorhandenen Mitgliedschaften sowie
archivierte Gruppen ohne Mitgliedschaften. Eindeutige Positionen und nichtnegative Werte,
aktive Filter-/Such-/Membership-Indizes. Byte-/Schema-Prüfungen für Snapshots bleiben bestehen;
rekursive normalisierte Schlüsselprüfung verbietet administrative Steuerfelder auch verschachtelt.

Migration wählt keine fehlende Legacy-Primärgruppe selbst. Bei inkonsistenten Altdaten
abbrechen, Backup prüfen und kontrollierte explizite Operatorentscheidung treffen. Kein
unbeaufsichtigtes Reparaturtool. Alte Revisionen bleiben unverändert. Rückkehr durch
getesteten Backup/Restore, kein destruktives automatisches Downgrade.
