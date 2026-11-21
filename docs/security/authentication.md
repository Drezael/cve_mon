# Authentifizierung T00.05.06

Lokale Benutzerkonten in PostgreSQL, keine öffentliche Selbstregistrierung, keine eingebauten
Standardzugangsdaten. Initialer Administrator wird einmalig lokal vom Betreiber provisioniert,
mit anschließend verpflichtender MFA-Einrichtung, bevor administrative Fachrechte nutzbar sind.
Benutzernamen NFKC+casefold eindeutig, Passwörter unverändert, mindestens 14 Zeichen bei Neuanlage,
maximal 1024 Zeichen, keine stillschweigende Kürzung. Argon2id, initial 64 MiB, t=3, p=1;
auf Zielhardware kalibrieren, Parameter im Hash und in Version speichern, Rehash bei Anmeldung.
Konstante Fehlerantworten und Dummy-Hashprüfung für unbekannte Benutzer, begrenzter Backoff.

Sitzung: zufälliger 256-Bit-Verifikator, SHA-256-Verifikator in PostgreSQL, kein Rohwert in DB/Logs.
Cookie __Host-cve-session: Secure, HttpOnly, SameSite=Strict, Path=/, kein Domain-Attribut.
Originbindung, CSRF-Nachweis bei allen schreibenden Browseraktionen; SameSite ersetzt CSRF nicht.
Idle-Timeout 30 min, absolute Laufzeit 12 h, frische Bestätigung für sensible Aktionen maximal 5 min alt.
Login, Passwortwechsel und Privilegwechsel rotieren Session-ID. Deaktivierung, Archivierung,
Sperrung, Passwortreset oder Rollenänderung erhöhen auth_version und widerrufen betroffene Sitzungen.
Keine Authentifizierung nur anhand Session-ID ohne geheimen Verifikator.

Voranmeldung verwendet separates __Host-cve-preauth, 5 min Laufzeit und CSRF-Token.
Login gibt bei MFA-Bedarf nur eine kontogebundene Challenge, keine vollständige Fachsitzung.
Erstmalige MFA-Einrichtung darf eine eingeschränkte Enrollment-Sitzung erhalten: nur eigene
CSRF-, Enrollment- und Confirm-Aktionen, keine Profil-/Fach-/Adminrechte. Danach Sessionrotation.
TOTP: 30-s-Schritt, 6 Ziffern, höchstens ±1 Zeitschritt, atomar gespeicherter letzter genutzter
Schritt verhindert Replay; begrenzte Versuche pro Challenge. Administrator-Systemrolle und jede administrative :manage-Berechtigung erfordern MFA.
Die Berechtigung wird erst nach bestätigter MFA nutzbar, auch bei benutzerdefinierten Rollen.
Recovery-Codes sind einmalig, hochentropisch und nur gehasht gespeichert; Ausgabe ausschließlich
einmalig an bestätigten Kontoinhaber. MFA-Reset benötigt frische starke Bestätigung oder einen
lokal autorisierten, auditierten Recovery-Prozess; niemals Schutz des letzten Administrators umgehen.

TOTP-Seeds authentifiziert verschlüsselt, key_id und extern bereitgestellter Schlüssel.
Schlüsselrotation/Backup getrennt von DB-Backup, keine entschlüsselbaren Seeds in Audit/Logs.
Einladungs-/Reset-Tokens haben Zweckbindung, kurze Frist (Einladung 24 h, Reset 30 min),
Single-Use und Hashverifikatoren. Ausgabe/Zustellung außerhalb normaler Benutzerlisten.

Technische Upload-Identität benötigt gültiges Clientzertifikat und separaten zufälligen API-Token,
HMAC-Verifikator mit externem Schlüssel, Scope inventory:submit und erlaubte Server-IDs.
Widerruf/Expiry und Principal-/Zertifikatsbindung werden bei jedem Request geprüft.
Dienstidentitäten sind getrennt und audience-gebunden; Details in internal-trust.md.

Grundlagen: [OWASP Sitzungen](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet),
[OWASP MFA](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html).
Parameter sind lokale v1-Entscheidungen und müssen in späteren Sicherheits-/Lasttests nachgewiesen werden.

POST /api/v1/dashboard/auth/reauthenticate bestätigt die eigene Sitzung erneut mit Passwort
und bei administrativen Rechten aktuellem TOTP-Code; Sessionrotation und neuer MFA-Zeitpunkt.
Sensible Admin-Writes verlangen eine höchstens 5 min alte starke Bestätigung.
