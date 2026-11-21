# Persönliche Gruppendaten wiederherstellen

Gruppen, Mitgliedschaften und persönliche Konfigurationsversionen werden mit der bestehenden Datenbank gesichert. Bei einer vollständigen Wiederherstellung müssen diese Tabellen konsistent zum selben Sicherungszeitpunkt wiederhergestellt werden. Laufende Frontends müssen anschließend den aktuellen Stand neu laden, damit alte Versionen nicht erneut eingereicht werden.

Die Diagnose `scripts.administration.manage all` prüft Besitzer, das leere historische Primärgruppenfeld, Serverreihenfolge und Datenbankrechte. Sie verändert keine Daten. Fehlgeschlagene Löschungen werden nicht automatisch wiederholt.
