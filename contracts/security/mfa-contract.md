# MFA v1

SHA1 / sechs ASCII-Ziffern / 30 s / maximal ±1 Schritt; monotone last_used_step.
MFA ist für alle Rollen optional und wird ausschließlich in den eigenen Kontoeinstellungen
aktiviert. Rollen und Bootstrap erzwingen keine Einrichtung. Nach freiwilliger Aktivierung
ist der zusätzliche Faktor beim Login erforderlich, bis er nach frischer eigener
Passwort-/MFA-Bestätigung in den Einstellungen deaktiviert wird.
Provisionierung nur mit frischer eigener Passwort-/gegebenenfalls MFA-Bestätigung,
Aktivierung erst nach bestätigtem Code. Eine begonnene Einrichtung sperrt die
bestehende Sitzung nicht und kann abgebrochen werden; beim Erneuern bleibt der
alte Faktor bis zur erfolgreichen Bestätigung des neuen aktiv.
AES-256-GCM mit versionierter privater Schlüsseldatei und Benutzer-AAD.

Enrollment-URI und zehn 256-Bit-Recovery-Codes sind ausdrücklich vorgesehene einmalige
geheime Ausgaben in autorisierten no-store-Antworten. Alle anderen Secret-Ausgaben,
Logs oder Eventpayloads verboten. Recovery benötigt Passwortkontext, erzeugt keine volle
Session und verlangt neuen bestätigten Faktor. Reauth-Nachweis fünf Minuten/einmalig.
