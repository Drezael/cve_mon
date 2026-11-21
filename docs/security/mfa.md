# TOTP-MFA

RFC 6238, SHA-1, sechs ASCII-Ziffern, 30 Sekunden; Fenster ±1 (konfigurierbar 0–1).
20 zufällige Secretbytes. last_used_step speichert den höchsten akzeptierten Schritt,
unter Benutzerzeilenlock atomar mit Sessionrotation/Audit. Ein bereits akzeptierter
Schritt wird auch in einer anderen Challenge abgewiesen. Bei Uhrabweichungen außerhalb
des Fensters ablehnen, nicht das Fenster beliebig erweitern.

Admin und user_admin benötigen MFA. Enrollment nur mit passwortbestätigter eingeschränkter
Session oder aktueller einmaliger Reauthentifizierung. Pending-Faktor ist an Session-ID
und fünf Minuten gebunden, ohne Bestätigung niemals aktiv. Nach Bestätigung wird MFA
auch für freiwillig eingerichtete Benutzer verpflichtend, bis eine spätere ausdrücklich
autorisierte Faktorverwaltung eine andere Richtlinie implementiert.

cryptography 50.0.2 / AES-256-GCM: frischer 96-Bit-Nonce, 128-Bit-Tag, AAD mit Benutzer-UUID.
Schlüsseldatei enthält active und maximal acht versionierte 32-Byte-Schlüssel; privat
0400/0600, kein Symlink. Schlüsselrotation: alten Key behalten, neuen aktiv setzen,
API neu erstellen; erfolgreiche Verifikation verschlüsselt mit dem aktiven Key neu.
Alten Key erst nach kontrollierter Prüfung aller relevanten Ciphertexte entfernen.
Verlust/Manipulation führt zu 503 und keiner zusätzlichen Sessionberechtigung.

Provisionierungs-URI nur bei autorisiertem Enrollment; Recovery-Codes einmal nach
Bestätigung. Beide Antworten no-store; keine Logs. Faktorenwechsel benötigt frische
MFA-Reauth, widerruft andere Sessions und bleibt bis Bestätigung eingeschränkt.
TOTP ist nicht phishingresistent; WebAuthn ist keine Funktion dieser Phase.
[RFC](https://www.rfc-editor.org/rfc/rfc6238), [AEAD](https://cryptography.io/en/latest/hazmat/primitives/aead/).
