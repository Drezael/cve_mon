# Authentifizierung

Die Oberfläche verwendet ausschließlich die Auth-Endpunkte aus Phase 8. Passwörter und MFA-Codes gehen per JSON-POST mit CSRF-Header an die gleiche HTTPS-Origin. Die __Host-Cookies bleiben Secure und HttpOnly; JavaScript liest kein Sitzungstoken. CSRF und temporäre MFA-Schlüssel verbleiben im Arbeitsspeicher. Nach POST wird der CSRF-Wert neu angefordert. Wiederherstellungscodes werden einmal angezeigt und beim Verlassen bzw. Abmelden verworfen.

Sessionprüfung erfolgt beim Einstieg, bei pageshow und begrenzt alle 60 Sekunden im sichtbaren Tab. 401, Logout und BroadcastChannel-Logout entfernen den privaten React-Baum und brechen laufende Requests ab. pagehide entfernt private Daten; pageshow validiert neu. Es gibt keinen Service Worker und keinen persistenten Browsercache für Fachdaten. Local Storage und Session Storage enthalten keine Anwendungsdaten.

MFA ist für alle Rollen optional. Aktivierung, Erneuerung und Deaktivierung erfolgen
ausschließlich unter Verwaltung → Kontosicherheit nach frischer Passwortprüfung
(bei bereits aktivierter MFA zusätzlich TOTP). Eine unbestätigte Einrichtung
aktiviert MFA noch nicht und kann abgebrochen werden. Rollen erzwingen keine MFA.
