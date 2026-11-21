# Dienstkonfiguration und Secrets

Pydantic Settings: explizite Constructor-Werte vor dienstbezogenen Umgebungsvariablen
vor nichtgeheimen Defaults. Keine automatische .env-Datei, keine eingebauten Passwort-
werte und kein Pydantic-Secrets-Fallback. Fehlende/ungültige Settings führen zu
ConfigurationError ohne Inputwerte; ServiceSettings hat CVE_SERVICE_, API CVE_API_.
Worker benötigen ohne DB/externes HTTP keine entsprechenden Credentials.

| Name (API-Umgebung) | Bedeutung |
|---|---|
| CVE_API_APP_ENV | Pflicht: development/test/production |
| CVE_API_LOG_LEVEL | DEBUG/INFO/WARNING/ERROR, Default INFO |
| CVE_API_HTTP_PORT | 1024–65535, Default 8000 |
| CVE_API_ALLOWED_HOSTS | JSON-Liste expliziter Hosts; cve-api/localhost/127.0.0.1 |
| CVE_API_READY_TIMEOUT | >0 bis 5 Sekunden; Default 1 |
| CVE_API_DATABASE__HOST | Pflicht-DNS, Compose cve-postgres |
| CVE_API_DATABASE__PORT | Default 5432, gültiger Port |
| CVE_API_DATABASE__USERNAME | Pflicht, Phase 6 api_reader |
| CVE_API_DATABASE__PASSWORD_FILE | Explizites privates Passwortfile |
| CVE_API_DATABASE__CA_FILE | Explizite vertrauenswürdige PostgreSQL-CA |
| CVE_API_DATABASE__POOL_SIZE | 1–10, Default 3 |
| CVE_API_DATABASE__MAX_OVERFLOW | 0–5, Default 0 |
| CVE_API_DATABASE__POOL_TIMEOUT | >0 bis 10 s; Default 2 |
| CVE_API_DATABASE__CONNECT_TIMEOUT | 1–10 s; Default 2 |
| CVE_API_DATABASE__STATEMENT_TIMEOUT_MS | 10–30000 ms, Default 2000 |

DatabaseSettings.hostaddr ist ausschließlich eine explizite native Transportadresse
für isolierte Hosttests; TLS prüft weiterhin den festgelegten DNS-Namen. Kein TLS-off-
Schalter. Secrets nur aus regulären Dateien, 0400/0600, O_NOFOLLOW/O_NONBLOCK,
Längenlimit, keine Leerdateien/mehrzeiligen Werte. Fehlermeldungen enthalten weder
Pfad noch Inhalt. Öffentliche CA separat; keine privaten Clientschlüssel im API-Image.

Logging akzeptiert ausschließlich bekannte Ereignisse und begrenzte Metadaten, keine
beliebigen Messages, Bodies, Querystrings, Header oder Tracebacks. Separate rekursive
Redaktion maskiert sensible Feldnamen, registrierte Secrets, private Schlüssel und
Credential-URLs. Settings-/Secret-Repräsentationen dürfen nicht als Debug-Nutzdaten
protokolliert werden. Log-Level schaltet diese Redaktionsgrenzen nicht ab.
