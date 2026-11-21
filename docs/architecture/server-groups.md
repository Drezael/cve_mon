# Persönliche Servergruppen

Seit Migration `00071_personal_server_groups` gehören Servergruppen ausschließlich einem Benutzer (`owner_id`). Auch ein Administrator verwaltet in dieser Ansicht nur seine eigenen Gruppen. Gruppen vergeben keine Serverrechte. Lesbare aktive Server lassen sich in beliebig vielen eigenen Gruppen organisieren; dieselben Server können von anderen berechtigten Benutzern unabhängig gruppiert werden.

Die bestehenden Tabellen `inventory.server_groups` und `inventory.server_group_memberships` werden weiterverwendet. Es gibt keine parallele Gruppenlogik. Bestehende Gruppen werden dem bisherigen Ersteller zugeordnet, bei Gruppen ohne Ersteller dem ältesten Administrator. Namen sind NFKC-/casefold-normalisiert je Besitzer eindeutig. Alte Primärgruppen werden entfernt; das historische Kompatibilitätsfeld muss NULL bleiben. Die alten globalen Gruppenpositionen und Primärgruppenbedingungen sind aufgehoben.

Die aktuelle API besteht aus `GET/POST /api/v1/dashboard/groups`, `PUT/DELETE /api/v1/dashboard/groups/{id}` und `PUT /api/v1/dashboard/servers/{id}/groups`. Alle Vorgänge prüfen die aktive Sitzung und `server:read`; Schreibvorgänge zusätzlich CSRF und eine kontoweite Konfigurationsversion im Request. Fremde Gruppen und nicht lesbare Server liefern 404. Die Besitzeridentität stammt immer aus der Sitzung. Doppelte Mitgliedschaften, unbekannte Felder und ungültige Versionsstände werden abgelehnt. Eine veraltete Version überschreibt keine Änderungen. Änderungen werden mit dem auslösenden Benutzer im Audit protokolliert und niemals automatisch wiederholt.

Eine Gruppenlöschung entfernt die Gruppe und ihre Mitgliedschaften, erhält aber sämtliche Server. Eine Serverlöschung entfernt seine Mitgliedschaften in allen Benutzergruppen über Fremdschlüssel und den bestehenden Löschdienst. Die Daten liegen persistent in PostgreSQL.

Die Oberfläche unter „Meine Servergruppen“ bietet Anlegen, Bearbeiten und Löschen. „Gruppen zuordnen“ ist in Serverliste, Serverdetails und Serververwaltung verfügbar. Die Serverliste gruppiert die aktuelle, gefilterte Ergebnisseite; mehrfach zugeordnete Server erscheinen in jeder ihrer Gruppen. Server ohne eigene Gruppenzuordnung erscheinen unter „Ohne Gruppe“. Der Gruppenfilter arbeitet serverseitig vor Pagination und zählt Server genau einmal.

Die früheren `/admin/groups`-, Gruppenarchivierungs-, Primärgruppen- und Gruppenreihenfolge-Endpunkte wurden entfernt. Globale Serverreihenfolge bleibt eine separate administrative Funktion. Historische Migrationsdateien bleiben unverändert.
