# Administratives Inventory-Schema

Phase 10 ergänzt mit Revision 00016 administrative Servermetadaten, globale Reihenfolge,
Actor-FKs, Primär-/Archivierungs-Constraints und zusätzliche Indizes. Vorhandene Tabellen und
Positionen bleiben die Datenquelle. Keine Inventarrollen erhalten administrative Writes.
[Datenmodell](../../../docs/database/administrative-inventory-model.md).

Phase 11 ergänzt Revision 00017: submission_identities und unveränderliche submissions
mit Originalbytes/JSON, separaten Hashes und Kanalprovenienz. Native Identitätsbindung,
Quotas und Append-only; INSERT/Metadaten-SELECT für die beiden Annahmerollen. Kein Payload-
SELECT, keine administrativen Writes. Bestehende Snapshots bleiben unberührt.
[Annahmelifecycle](../../../docs/architecture/inventory-submission-lifecycle.md).
