# Audit und Datenminimierung Phase 23

Audit und historische Evidenz bleiben append-only mit Datenbankrechten/Triggern. Mutation, Actor, Korrelation, Grund und Version werden über die bestehenden Servicewege gespeichert. Die neue Lesesicht ermöglicht weder Historienänderungen noch unzulässige Aggregation. Anwendungssuperuser und freie SQL-Diagnose werden nicht eingeführt.

Zentrale JSON-Logs enthalten Status/Latenz und Korrelationskennungen; keine Bodies oder privaten Feldwerte. Dateigröße/Anzahl sind durch Dockerloglimits begrenzt. Statusrohmessungen besitzen begrenzte Retention; Audit wird nicht pauschal mit Messwerten gelöscht. Manipulationsnachweis schützt gegen Runtimeidentitäten, nicht gegen einen vollständig kompromittierten Host-/DB-Owner. Für unabhängigen revisionssicheren Export bleibt Phase 24 verantwortlich.
