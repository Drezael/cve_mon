# Versionierte PostgreSQL-DDL

Alembic implementiert die Phase-3-Schemas durch explizite DDL in versions/.
Kontrollierter Einstieg: `make db-migrate`; nie automatisch bei jedem Containerstart.
Transaktionaler Advisory-Lock, eine lineare Kette, geschützter NOLOGIN-Owner.
Wiederholungen auf Head erhalten Daten; Fehler und SQL-Abbruch rollen DDL/Versionsstand zurück.
Downgrade erfolgt über einen geprüften isolierten Backup/Restore statt destruktiver DROP-Logik.
# Regeln ab dem Review vom 25.11.2026

Ausgelieferte Revisionen bleiben unverändert; ihre Hashes stehen in
`configuration/quality/migration-baseline.json` und werden durch einen Regressionstest geprüft.
Neue Revisionen deklarieren vollständige Zielfunktionen/-views und die notwendigen Rechte.
Keine Textpatches auf formatierten `pg_get_functiondef()`-Ausgaben einführen. Die neue
Revision 00077 zeigt diesen Stil. Alte Instanzen werden vorwärts migriert; bei Fehlern gelten
die überprüften Backup-/Restoreverfahren. Neuinstallation, Upgrade aus einem älteren Stand
und abweichende Altdefinitionen müssen isoliert getestet werden.
