# Persönliche Gruppen und Zugriffsrechte

Gruppen organisieren die bereits lesbaren Server eines Benutzerkontos. Sie vergeben oder erben keine Rechte. Auch Administratoren dürfen über die Gruppen-API keine fremden Gruppen lesen oder ändern. Besitzer werden aus der geprüften Sitzung ermittelt, nicht aus Uploads oder Requestfeldern.

Jeder Endpunkt prüft `server:read`, jede Änderung zusätzlich CSRF. Die kontoweite Versionsnummer verhindert konkurrierende Überschreibungen. Fremde Gruppen und nicht lesbare Server liefern 404. Gruppenoperationen benötigen keine administrative Rollenzuweisung und keine erneute Passworteingabe. Die auslösende Benutzeridentität wird im Audit gespeichert.

Die früheren administrativen Rechte `group:create/update/delete/assign/primary:assign/reorder` sowie ihre API-Endpunkte wurden entfernt. Die Organisationslogik besitzt keine Primärgruppe. Siehe [Architektur](../architecture/server-groups.md).
