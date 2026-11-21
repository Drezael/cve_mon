# Serviceauthentifizierung

Zwei unabhängige zufällige Schlüssel schützen Notification→n8n-Webhooks und n8n→Notification-
Callbacks. Ausschließlich Header-Authentifizierung, niemals Query-Parameter. n8n hält sie
als verschlüsselte httpHeaderAuth-Credentials; SMTP-Zugangsdaten werden nicht übergeben.
Die interne API prüft den Namespace-Proof, einen konstantzeitlichen Schlüsselvergleich,
maximal 2048 Byte Body, geschlossene Datenmodelle sowie zufällige Run-/Request-UUIDs.

Ein Run ist fünf Minuten gültig. Claim ist einmalig; wiederholtes Execute kann keinen
zweiten SMTP-Versuch nach submitting/Relayannahme freigeben. Tick-Replays innerhalb einer
Minute sind persistent idempotent. n8n darf keine Actor-/Empfänger-/Zielserveridentität wählen.

make n8n-rotate ersetzt den Service-Schlüssel und importiert die verschlüsselten Credentials.
Der alte Callback-Schlüssel wird maximal eine Stunde akzeptiert; Neustarts setzen dieses
Zeitfenster nicht zurück. Workflows haben keinen Environment-/Dateizugriff; Community Nodes,
Telemetrie und öffentliche n8n-API sind deaktiviert. Für die unabhängige Dienstprüfung
ist zusätzlich der originale PostgreSQL-Knotentyp freigeschaltet. Sein verschlüsseltes
Credential verwendet `workflow_control`, TLS mit vollständiger Zertifikatsprüfung
und den festen Funktionsaufruf `status.watchdog_tick`. Die Rolle hat keine direkten
Schreibrechte auf CVEs, Inventare oder Neustartbelege. Nur die geschützte Funktion
autorisiert anhand gespeicherter Beobachtungen, Wartungsfenster und Neustartlimits.
Der Host-Agent darf Prüfwerte speichern und freigegebene Neustarts ausführen, jedoch
keine Watchdog-Entscheidung treffen. Der n8n-Container erhält keinen Docker-Socket.
Die Editoroberfläche besitzt keine öffentliche Route.
