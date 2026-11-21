# Audit und Änderungsverlauf

Unveränderliche minimierte Projektion aus security.audit_log, findings.audit_events und automation.notification_audit. Zugriff benötigt audit:read. Admin sieht zulässige globale Ereignismetadaten, andere Berechtigte nur eigene actor_user_id-Ereignisse. Ausgabe enthält ID, Zeit, tatsächlichen Akteur, Aktion, Objekt und Ergebnis; keine Rohpayloads, Credentialwerte oder beliebigen Metadaten. Finding-Historien und Notification-Versionshistorien bleiben zusätzlich mit ihren bestehenden Fachrechten zugänglich. Es gibt keinen Schreib-, Lösch- oder Actor-Auswahl-Dialog für Auditdaten.


Ohne zugeordneten menschlichen Akteur zeigt das Feld „Benutzer“ den Dienst aus
`actor_service`, beispielsweise `Service: importer`. Die Projektion verwendet die
protokollierte technische Identität beziehungsweise Ausführungsrolle; bei den
separaten Notification-Audits den zuständigen Notification-Dienst. Menschliche
Benutzer haben Vorrang. `actor_user_id` bleibt in API und Datenbank eine unveränderte
Benutzerreferenz; es werden weder Service-Namen in UUID-Felder geschrieben noch
historische Auditereignisse umgeschrieben. Die bestehenden Leserechte gelten auch
für die ergänzte Dienstangabe.


Für menschliche Akteure löst die Projektion `actor_user_id` über `security.users`
zum aktuellen `actor_username` auf. Im Feld „Benutzer“ erscheint dieser Benutzername;
die UUID bleibt ausschließlich als unveränderte Referenz in den Auditdaten erhalten.
Ist kein Benutzername verfügbar, wird kein kryptischer ID-Ersatz angezeigt.
