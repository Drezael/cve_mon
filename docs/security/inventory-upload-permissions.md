# Berechtigungen beim Inventarupload

`server:inventory:manage` erlaubt angemeldeten Benutzern, Server aus einem Inventar 1.2
anzulegen und eigene beziehungsweise ausdrücklich zum Upload freigegebene Server zu
aktualisieren. Der Ersteller erhält atomar Leser-, Upload- und Finding-Leserechte.
Administratoren benötigen keine weitere Upload-ACL. Viewer und Analyst bleiben standardmäßig
lesend. Eine Datei kann keine Benutzer-, Gruppen-, ACL- oder Prioritätseinstellungen setzen.
Das bisherige Recht `inventory:upload:dashboard` bleibt für alte API-Integrationen erhalten;
vorhandene Rollen mit Upload- oder Serveranlageberechtigung erhalten bei der Migration das
zusammengefasste neue Recht. Neue Rollen können dieses einzeln delegierbare Recht enthalten.

Technische Collector-Zugänge sind mTLS- und Bearer-gebunden. `inventory:discover` verwendet
zusätzlich einen festen aktiven Benutzer mit `server:inventory:manage` und dessen Serverrechte.
Ein Credential kann damit mehrere Server erfassen. Benutzerdeaktivierung oder Rechteentzug
sperren diesen Zugang. Bisherige `inventory:submit`-Tokens bleiben auf genau einen Server begrenzt.
Serveridentität ersetzt keine Authentifizierung; fremde Bestandsserver sind nicht übernehmbar.

[Dateiformat und Betrieb](../operations/server-onboarding.md)
