# Technische Inventare und Administration trennen

Administrative Writes ausschließlich dashboard_admin in kontrollierten Backendtransaktionen.
api_ingest, inventory_processor, matcher, importer, enricher, event_dispatcher und api_security
besitzen keine Writes auf Primärgruppe, globale Position, Kritikalität, Gruppenreihenfolge
oder Mitgliedschaften. Native Tests prüfen jede dieser Grenzen mit echten Logins.

Snapshots referenzieren bereits registrierte Server-UUIDs. Unbekanntes wird durch FK
abgelehnt, archivierte/inaktive Ziele durch bestehende Snapshotguards. Keine automatische
Registrierung und keine Verbindung zu verwalteten Servern. Administrative API schreibt
keine technischen Betriebssystem-/Paket-/Snapshotdaten.

Native rekursive Schlüsselprüfung normalisiert NFKC, Schreibweise und Trennzeichen für
group_id/group_ids/primary_group_id/group_sort_order/display_order/sort_order/groups/
server_groups sowie Kritikalität/Exposition/Umgebung. Verschachtelte arrays/objects werden
geprüft; Phase-0-Inventarschema bleibt zusätzliche Allowlist. Inventare erhalten keine
administrative Hoheit aus technischen Hostnamen, Tags, Paketen oder CVEs.

Phase 11 implementiert erst die tatsächlichen technischen und Dashboard-Uploads. Dort
mTLS/Bearer/inventory:submit strikt von Browser/CSRF/inventory:upload:dashboard + ACL trennen.
Beide Wege müssen die bestehenden Grenzen unverändert übernehmen.
