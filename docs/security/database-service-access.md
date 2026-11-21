# Dienstbezogene PostgreSQL-Zugriffe

Phase-3-Rechte unverändert. cve-api in Phase 6 ausschließlich api_reader. Gemeinsames
DatabaseSettings akzeptiert nur bekannte Runtime-Rollen; postgres_admin, postgres_owner,
cve_migrator und n8n_app sind für reguläre Services abgelehnt. Weitere API-Kontexte
werden erst mit den autorisierten Fachoperationen ausdrücklich provisioniert.
DatabaseRegistry enthält getrennte Engines pro explizitem Kontext, kein SET ROLE und
keine Auswahl von Schreibrechten durch Request-Header.

TLS verify-full und explizite CA, Psycopg 3 asynchron, SQLAlchemy AsyncEngine.
Poolgröße 3, Overflow 0, Pooltimeout 2 s, Connecttimeout 2 s, Statementtimeout 2 s,
Pre-Ping, Recycle 300 s; pro Prozess begrenzt. Keine automatische Schemaanlage oder
Migration. Parameter nicht in Fehlerausgaben (hide_parameters), kein SQL-Echo.
Sessions/Transaktionen respektieren PostgreSQL-RLS und Trigger; insbesondere keine
Inventar-basierten Gruppen-, Primärgruppen- oder Sortieränderungen.

Integrationstests verwenden ein eigenes DB-Testprojekt: echte Grants, Commit,
Rollback/Cancellation, parallele Sessions, SQL- und Timeoutfehler, Poolerschöpfung,
Neustart und gesperrte DDL/Rollenübernahme. Bestehende Datenbanken bleiben unangetastet.
