# Versionierte PostgreSQL-DDL

Alembic implementiert die Phase-3-Schemas durch explizite DDL in versions/.
Kontrollierter Einstieg: `make db-migrate`; nie automatisch bei jedem Containerstart.
Transaktionaler Advisory-Lock, eine lineare Kette, geschützter NOLOGIN-Owner.
Wiederholungen auf Head erhalten Daten; Fehler und SQL-Abbruch rollen DDL/Versionsstand zurück.
Downgrade erfolgt über einen geprüften isolierten Backup/Restore statt destruktiver DROP-Logik.
