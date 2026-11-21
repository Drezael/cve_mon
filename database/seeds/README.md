# Versionierte Initialdaten

Rollen, Berechtigungen und technische Typ-/Quellenkataloge sind explizite INSERTs mit
Konfliktschutz innerhalb der Alembic-Revisionen 0004, 0006, 0008, 0009, 00010 und 00011.
Es gibt keine zweite Seed-Wahrheit und keine Standardbenutzer oder bekannten Credentials.
Rechteänderungen erhalten eine neue Migration; keine Seeddatei beim Containerstart erneut ausführen.
