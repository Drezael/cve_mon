# Authentifizierungsgrenzen T00.04.02–06

| Operation | Identität / Schutz | Objektprüfung / Besitzer |
|---|---|---|
| POST /api/v1/inventories | HTTPS, mTLS UND UploadToken, inventory:submit | server_id im Tokenbereich; api_ingest |
| POST /api/v1/dashboard/inventories/upload | DashboardSession UND CsrfToken, inventory:upload:dashboard | Formular-ID = Datei-ID, aktuelles Serverrecht; api_ingest |
| /api/v1/dashboard/admin/* | Menschliche Sitzung, MFA für Admin, CSRF bei Writes | Je Operation x-permission und Objektbereich; dashboard_admin/api_security |
| Fachliche GET-APIs | DashboardSession und Leserecht | Daten/Counts/Reports auf erlaubte Server begrenzen |
| Finding-Statusänderung, Reportauftrag | Sitzung, CSRF und Fachrecht | Delegierter Actor wird durch zuständigen Dienst geprüft |
| Deployment-Status | Sitzung, deployment:status:read | Keine Zielparameter, no-store und feste Manifestziele |
| Authentifizierungsstart | PreAuthCookie und CSRF; /auth/csrf öffentlich | PreAuth hat keine fachlichen Rechte, MFA-Challenge kontogebunden |
| /internal/v1 und /health | InternalMTLS UND ServiceIdentity | Issuer, audience, expiry, Caller-/Methoden-Allowlist |

Security-Objekte mit mehreren Einträgen im selben Objekt bedeuten UND, keine alternativen
Akzeptanzwege. Technische Upload-Tokens werden an sämtlichen Dashboard-/Admin-APIs abgewiesen.
Server-/Gruppenadministration liegt ausschließlich im menschlichen Dashboard-Kontext.
Interne Job-APIs erlauben keine beliebigen Jobtypen, Upstream-URLs oder Gruppenkommandos.

Login stellt vor MFA keinen vollständigen Session-Cookie aus. Voranmelde- und eingeschränkte
MFA-Enrollment-Sitzungen dürfen nur ihre eigenen Challenge-/Enrollment-Aktionen ausführen.
MFA-Verifikation konsumiert eine kontogebundene kurzlebige Challenge; keine freie user_id.
Account-Tokens für Einladung/Reset sind separat von technischen Upload-Tokens.

Zugangsdaten werden nie in Beispielen dokumentiert. Neu erzeugte Upload-Tokens, TOTP-
Provisionierungsdaten und Recovery-Codes dürfen ausschließlich im jeweils autorisierten
Einmal-Ausgabeablauf an ihren legitimen Empfänger erscheinen; no-store und kein Logging.
Alle normalen User-/Profil-/Session-Antworten enthalten keine Geheimnisse oder Verifikatoren.
