# Phase-9-Performancenachweis

Stand: 06.11.2026; isolierter lokaler PostgreSQL-/API-Test, keine Produktionslast.

1000 Benutzer, 200 Rollen, 4000 Server, 500 explizite Grants. 24 parallele gefilterte
Seitenabfragen benötigten insgesamt 0.179 Sekunden. Pro Seite 12 SQL-Abfragen,
unabhängig vom getesteten Seitenlimit 1 beziehungsweise 100; kein N+1 pro Server.
EXPLAIN ANALYZE zeigt Index Scans auf user_server_access_pkey und servers_pkey.
Der gemessene Plan für 25 Ergebnisse benötigte 0.058 ms.

ACL-Filter greifen vor Suche, Pagination und Aggregation; Gruppen liefern keine zusätzlichen
Rechte. Der Test prüft die konstant begrenzte Queryanzahl und ACL-korrekte Ergebnisse,
keine absolute Latenzgarantie. Größere Produktionslast bleibt in Phase 23 zu messen.
Rohdaten: .runtime/test-reports/phase-09-performance.json (lokal, ignoriert).
Automatisiert: tests/authorization/integration/test_performance.py.
