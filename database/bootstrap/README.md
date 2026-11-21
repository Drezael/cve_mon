# Bootstrap und Provisionierung

Erstinitialisierung leerer Volumes: infrastructure/postgres/initdb/01-bootstrap.sh.
Kontrollierte, wiederholbare Rollen-/CONNECT-Provisionierung: scripts/database/manage.py.
Keine Fach-DDL im Image-Bootstrap, keine Passwortwerte in SQL-/Env-Vorlagen.
