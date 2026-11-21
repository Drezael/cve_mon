# Recovery und Passwortreset

Zehn unabhängige Recovery-Codes mit je 256 Bit Entropie; nur SHA-256-Verifikatoren
persistiert. Anzeige einmal beim bestätigten Enrollment, verbleibende Anzahl nur im
eigenen vollständigen Sessionkontext. Verbrauch atomar unter Benutzerlock, nach Passwort
und in gültiger mfa_pending-Session mit CSRF/Origin und Versuchslimit.

Recovery widerruft Sessions und bisherigen Faktor, rotiert in mfa_recovery. Keine
vollständige Identität, bevor ein neues TOTP bestätigt wurde. Ein unabhängiger Passwort-
Login bleibt mfa_pending; er darf den laufenden Recovery-Kontext nicht übernehmen.
Weitere vorhandene Recovery-Codes können bei Verlust der eingeschränkten Session einen
neuen kontrollierten Ablauf starten. Neue Codes widerrufen alle alten.

Reauth: aktuelles Passwort, bei vorhandenem MFA-Faktor frischer unverbrauchter TOTP;
Sessionrotation, maximal fünf Minuten, sessiongebunden, für kritische Änderung einmal
verbrauchbar. Passwortänderung verlangt diese Bestätigung und aktuelles Passwort.

ResetTokens sind interne Primitive für eine künftig autorisierte unabhängige Zustellung:
UUID + 256 Bit, zweck-/benutzergebunden, 15 Minuten, nur Digest, atomarer Einmalverbrauch.
Reset erhöht Credential-/Authversion, widerruft alle Sessions und andere Tokens, behält
MFA. Keine öffentliche Resetroute, keine E-Mail-Zusage, kein Versand vor Phase 19.
