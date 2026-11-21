# Server und persönliche Gruppen

`inventory.server_groups.owner_id` referenziert den Besitzer in `security.users`. Namen sind normalisiert pro Besitzer eindeutig. `inventory.server_group_memberships` bildet die n:m-Beziehung ab. Beim Löschen einer Gruppe oder eines Servers entfernt PostgreSQL dessen Mitgliedschaften per `ON DELETE CASCADE`.

`inventory.personal_group_revisions` speichert die Version der persönlichen Gruppenkonfiguration. Gruppen und Mitgliedschaften werden gemeinsam mit Version und Audit transaktional geändert. Die Daten liegen im bestehenden PostgreSQL-Volume und überleben Prozessneustarts und Versionsrollouts.

Migration 71 überführt vorhandene Gruppen zum bisherigen Ersteller beziehungsweise ältesten Administrator. Das historische `primary_group_id` bleibt ausschließlich aus Kompatibilitätsgründen in bestehenden Serverprojektionen vorhanden und muss NULL sein. Eine Primärgruppenlogik gibt es nicht mehr. Alte Gruppenpositionsbedingungen sind aufgehoben; Gruppen werden alphabetisch dargestellt.
