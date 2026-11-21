# Phase-10-Performancenachweis

Stand: 07.11.2026. Isolierte lokale PostgreSQL-/API-Baseline; keine Produktionslast.

2000 Server, 100 Gruppen, 4000 Mitgliedschaften, 500 direkte Grants. 24 parallele
ACL-gefilterte Seitenabfragen benötigten zusammen 0.243 Sekunden.
Zwölf SQL-Abfragen pro Seite, unabhängig von Limit 1 oder 100, keine Abfrage pro Ergebnis.
Der EXPLAIN-ANALYZE-Plan ist unter .runtime/test-reports/phase-10-performance.json gesichert;
er verwendet den Index der direkten Server-ACL. Globale relative Neuordnung auch für
mehr als 100 Objekte erfolgreich, Requestgröße unabhängig vom gesamten Bestand.

Die Schreibseite verwendet bewusst eine feste globale Sperrreihenfolge und eine O(N)-
Bulk-Neuordnung. Dies ist eine nachvollziehbare lokale Baseline, kein Produktions-SLA.
Sehr große Bestände und höhere Schreibparallelität werden in Phase 23 weiter vermessen.
[Testmatrix](phase-10-test-matrix.md).
