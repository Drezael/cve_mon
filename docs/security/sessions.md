# Sessions und Cookies

Token: zufällige Lookup-UUID plus unabhängiger 256-Bit-Verifikator. Nur dessen SHA-256-
Digest liegt in security.sessions; Token nur im Cookie, niemals URL/Local Storage/Log.
__Host-cve-session: Secure, HttpOnly, SameSite=Strict, Path=/, kein Domain. Anonymer
Voranmeldekontext separat in __Host-cve-login, ohne Benutzerbindung oder Fachrechte.

Native auth_version und origin werden geprüft, zusätzlich credential_version,
runtime_version=1, Kontostatus und aktuelle MFA-Pflicht. Alte vorbereitende Sessionzeilen
mit runtime_version=0 werden nicht übernommen. Kein Vertrauen in Rollen-/Benutzerheader.
Default: Admin idle 15 Minuten/absolut 8 Stunden; Benutzer 30 Minuten/12 Stunden;
Challenge 5 Minuten/5 Minuten. Serverseitige DB-Zeit. Idle-Verlängerung überschreitet
nie das absolute Ende. Settings erlauben kürzere, keine längeren Grenzen.

Login/MFA/Reauth erzeugen neue Identitäten. Reauth mit erneutem Passwort und ggf. Faktor
ist eine neue bestätigte Anmeldung und erhält eine neue begrenzte Lebensdauer. Logout
widerruft sofort, logout-all alle eigenen Sessions; Passwortreset/-änderung ebenfalls.
Kontodeaktivierung und Authversionänderung widerrufen Laufzeitsessions zusätzlich per
nativem Trigger. Auch eine spätere Reaktivierung macht alte Tokens nicht erneut gültig.
Parallelität ist über den Benutzerzeilenlock konsistent; bereits vorher erfolgreich
geprüfte Requests werden dadurch nicht rückwirkend abgebrochen.

Wartung alle 60 Sekunden (30–300 konfigurierbar): begrenzte Batches für abgelaufene
CSRF-/Rate-Kontexte und Sessionwiderruf; Session-/Reset-Daten älter als 30 Tage werden
in Batches von höchstens 200 entfernt. Cleanup läuft unabhängig mit eigener Session,
stoppt beim Lifespan-Ende und führt keine Fachänderungen aus.
