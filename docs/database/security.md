# Persistente Sicherheitsdaten

Alle Identitäten sind UUID. `security.users` besitzt username/email mit generierten
NFKC+casefold-Normalformen und UNIQUE, display_name, status
pending_activation/active/locked/disabled/archived, auth_version, version, Zeitpunkte und
archived_at. `password_credentials` speichert ausschließlich strukturell geprüfte
Argon2id-PHC-Hashes, algorithm, parameters_version, changed_at und must_change.
Keine Benutzer, Passwörter oder produktiven Token werden geseedet.

`roles`, `permissions`, `role_permissions`, `user_roles` speichern RBAC mit gültigen FKs
und eindeutigen Zuordnungen. Versionierte Seeds enthalten admin, user_admin,
security_analyst, viewer und die expliziten menschlichen Fachrechte. Öffentliche/Preauth-/
Session-/Dienstscopes sind keine zuweisbaren menschlichen Berechtigungen. Systemrollen
und deren Permissionzuordnungen sind durch RLS vor Runtime-Änderungen geschützt;
api_security verwaltet nur benutzerdefinierte Rollen und bekannte Zuordnungen.
Delegierbarkeit und letzte-Admin-Prüfung sind zusätzliche API-Aufgaben in Phase 9.

`user_server_access(user_id,server_id)` speichert can_read/can_upload und granted_by.
`user_group_access(user_id,group_id)` vermittelt ausschließlich Lesen.
`effective_server_access` vereinigt Leserechte und hält Uploads an direkte Serverfreigaben
gebunden. Ein Gruppenwechsel erweitert keine Upload-Allowlist. Aktueller Kontostatus,
globale Aktionsberechtigung und Objektfreigabe müssen in späteren API-Transaktionen gemeinsam
geprüft werden. Service-DB-Logins sind keine Benutzeridentitäten; die Datenbank filtert daher
Fachzeilen nicht nach einem vom Client wählbaren user_id-Sessionparameter.

| Tabelle | Geschützte Speicherung |
|---|---|
| sessions | user_id, UNIQUE verifier bytea(32), csrf_verifier bytea(32), auth_version, origin, created_at/last_seen_at, expires_at/idle_expires_at, revoked_at, mfa_verified_at |
| mfa_methods | user_id, kind=totp, ciphertext >=32 Bytes, externer key_id, verified_at, last_used_step, revoked_at |
| recovery_codes | user_id, global eindeutiger 32-Byte-Verifikator, created_at/used_at |
| account_tokens | user_id, purpose activation/password_reset/email_change/mfa_reset, global eindeutiger 32-Byte-Verifikator, Ablauf/Nutzung/Widerruf, issued_by |
| technical_principals | name UNIQUE, certificate_san UNIQUE, status active/disabled, version |
| api_tokens | principal_id, global eindeutiger 32-Byte-Verifikator, key_id, scope ausschließlich inventory:submit, Ablauf/Widerruf |
| principal_server_access | explizite technische Server-Allowlist, PK(principal_id,server_id) |

Die DB erzwingt Form, Eindeutigkeit, Beziehungen und Ablaufreihenfolge. Sie kann anhand eines
Bytearrays keine echte Verschlüsselung oder CSPRNG-Erzeugung beweisen. Argon2-Kosten,
authentifizierte TOTP-Verschlüsselung, HMAC-/Hash-Verifikation, MFA-Anti-Replay, Cookie-/CSRF-
Prüfung und frische starke Bestätigung werden in Phase 8/9 implementiert, nicht durch Seeds simuliert.
Schlüssel gehören in externe Secretdateien und separate verschlüsselte Sicherung.

Nur api_security darf Authentifizierungstabellen lesen. api_ingest besitzt kein SELECT auf
Tokenverifikatoren: `authorize_upload(verifier,server_id,certificate_san)` gibt ausschließlich
einen passenden aktiven Principal mit nicht abgelaufenem/unwiderrufenem Token und expliziter
Serverfreigabe zurück. Die SECURITY-DEFINER-Funktion hat den NOLOGIN-Owner, festen search_path
und ein einziges explizites Runtime-EXECUTE-Grant. Die API muss ihren mTLS-Vertrauenseingang
zusätzlich absichern. Reporter/Matcher/Processor/Statusrollen lesen keine Authgeheimnisse.
`user_directory` gibt nur öffentliche Kontofelder frei; `notification_recipients` nur aktive
Empfänger für notification. Keine Loginimplementierung oder öffentliche Registrierung vorhanden.

`system.invariant_locks['last_active_administrator']` stellt den transaktionalen Sperrpunkt für
den späteren Schutz des letzten aktiven, MFA-fähigen Administrators bereit. Phase 9 sperrt
und prüft denselben Datensatz bei Rollen-/Benutzer-/MFA-Änderungen. Phase 3 implementiert
weder die vollständige Fachregel noch einen produktiven Bootstrap-Administrator.
