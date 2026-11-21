# PostgreSQL-Optimierung Phase 23

Zwei gezielte Änderungen aufgrund tatsächlicher Pläne: api_security verwendet jit=off, weil Kompilationszeit die kurzen Requestabfragen dominiert. Migration31 ergänzt dashboard.server_list_index als günstige eindeutige Server-/Inventarsortierprojektion. Die API materialisiert die berechtigte gefilterte Seite und liest Details über eine parametrisierte Lateralprojektion mit OFFSET0. Dadurch wird die volatile breite Evidenzsicht nicht für den gesamten Serverbestand vor der Pagination ausgewertet.

Filter, Sortiermapping, Gruppenreihenfolge, Rechte, Gesamtzahl und Feldminimierung bleiben erhalten. Keine neue Matchingsemantik, kein Cache und keine fachlichen Tabellenupdates. Keine neuen Indizes ohne Queryplannachweis. Vorhandene Paket-/Snapshot-/Claim-/Outboxindizes werden weiter durch native EXPLAIN-Tests geprüft. Autovacuum und Poolbudgets bleiben unverändert.
