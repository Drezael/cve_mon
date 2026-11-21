# ADR-0028: Server, Gruppen und manuelle Reihenfolgen

Status: accepted. Datum: 07.11.2026.

Die administrative Serververwaltung verwendet die bestehenden inventory-Tabellen und einen
expliziten dashboard_admin-Pool im bestehenden cve-api. Keine dynamische Rollenwahl,
keine neue Infrastruktur und keine Schreibrechte für technische Inventarrollen.

Jede Mutation prüft aktuelle Session/MFA/CSRF, endliches Rollenrecht und Einmal-Reauth in
derselben PostgreSQL-Transaktion wie Domänenänderung, Audit und Outbox. Starke If-Match-
Bedingungen schützen Objekt- und Sortierrevisionen. Native deferred Constraints schützen
Primärmitgliedschaften und leere archivierte Gruppen auch unter direkter SQL-Konkurrenz.

Die erste Implementierung verwendet eine feste globale Security-/Inventory-Lockreihenfolge.
Das begrenzt Schreibparallelität bewusst, ermöglicht aber deterministische Konfliktbehandlung
mit unabhängigen Revisionen je Sortierkontext. Relative Befehle begrenzen die Requestgröße;
Bulk-Neuordnung bleibt O(N). Größere Produktionsbestände werden in Phase 23 vermessen.

Archivierung erhält Historie und Mitgliedschaften. Historische Positionen bleiben reserviert;
Restore hängt kontrolliert an. Gruppen verleihen keine ACLs. Registrierung erzeugt zufällige
UUIDs und keine technischen Inventardaten. Keine stille Primärgruppenreparatur bei Migration.

[Architektur](../server-management.md), [Integrität](../group-memberships.md),
[Sortierung](../manual-ordering.md), [Datenhoheit](../../security/inventory-administration-isolation.md).
