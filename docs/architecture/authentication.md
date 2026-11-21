# Lokale Authentifizierung

cve-api 0.8.0 verwendet PostgreSQL security, den vorhandenen Resources-/Lifespan-
Mechanismus und kurze explizite SQLAlchemy-/Psycopg-Transaktionen. Eigener api_security-
Pool neben dem unveränderten Reader-Pool, kein SET ROLE und kein globales Sessionobjekt.
Kein Redis, JWT-Browserstore, IdP oder zusätzlicher Authentifizierungsdienst.

Nginx ist die einzige Browsergrenze: Dashboard-HTTPS-Origin, überschriebene Proxy-/IP-
Header und privates zufälliges Gateway-Geheimnis. AuthBoundary prüft diese Grenze vor
JSON-Verarbeitung, begrenzt Body auf 8 KiB und Lesezeit auf 5 Sekunden. HTTP zwischen
Nginx und API bleibt auf cve_internal; PostgreSQL benutzt weiterhin verify-full-TLS.
Die separate API-Domain hat keine Browser-Authrouten. Direkter Backendzugriff mit
gefälschten Identitäts-/Forwarded-/Gateway-Headern gewährt keinen Zugang.

GET csrf erzeugt einen fünf Minuten gültigen anonymen Voranmeldekontext oder eine neue
CSRF-Challenge für eine gültige Session. POST login verbraucht den Voranmeldekontext,
prüft persistierte Limits, verifiziert Argon2id außerhalb einer offenen DB-Transaktion
und prüft Konto/Credential-Version unter Benutzerzeilenlock erneut. Fehlversuche müssen
mit neuem GET csrf beginnen. Keine Kontosperrung durch Änderung des administrativen Status.

Ohne MFA-Bindung erhält ein aktiver Benutzer eine vollständige Session. Rollen erzwingen keine MFA-Einrichtung;
die freiwillige Aktivierung in Kontosicherheit setzt mfa_required. jemals aktivierte MFA erfordert auch nach Faktorverlust
weiter einen zweiten Faktor beziehungsweise kontrollierten Recovery-Code. Unvollständige
Zustände besitzen ausschließlich Authentifizierungsrechte. Nach MFA/Enrollment/Reauth
neue Sessionidentität, alte Identität widerrufen. Recovery führt ausschließlich in
mfa_recovery und neues bestätigtes Enrollment. Kein allgemeiner Bootstrap-Endpunkt.

Ein Benutzerzeilenlock serialisiert Security-Änderungen; anschließend werden Session-/
Faktor-/Tokenzeilen geprüft und geändert. So können TOTP-/Recovery-/Reset-Verbrauch und
Sessionrotation nicht parallel doppelt gewinnen. Bei Credential-Änderung steigen
credential_version und der vorhandene globale auth_version; alle Sessions werden widerrufen.
Fachabhängigkeiten verwenden authenticated_user, prüfen bei jedem Aufruf Konto, Version,
Zeiten, Widerruf und aktuelle MFA-Pflicht; Rollen-/Objektberechtigungen ergänzt Phase 9.

Audit/User-/Login-Event und auth.security-Outbox werden in derselben Transaktion gespeichert.
Feste Aktionen, UUID-Korrelation, keine Passwörter/OTP/Tokens oder Provisionierungsdaten.
Rollback veröffentlicht kein Event. Keine produktiven Outbox-Ziele oder n8n-Workflows.
[Bedrohungsmodell](../security/authentication-threat-model.md), [Vertrag](../../contracts/api/authentication.openapi.yaml).
