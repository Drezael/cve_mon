# HTTP- und Dienstgrenzen

In Phase 6 keine Authentifizierung durch Header. Forwarded/X-Forwarded und
Client-/SSL-/User-/Role-Identitätsheader werden vor der App entfernt; Uvicorns
Proxyinterpretation ist abgeschaltet. Hostnamen explizit, keine Wildcards. Keine
CORS-Freigaben, Docs/OpenAPI/Redoc deaktiviert, keine Slash-Redirects. Phase-0-OpenAPI
bleibt der verbindliche Fachvertrag und wird nicht durch eine leere Generierung ersetzt.

Request-ID akzeptiert UUID oder Nginx-32-Hex und normalisiert zu UUID; ungültige,
überlange oder doppelte Werte erzeugen neue IDs. Korrelations-ID separat, ContextVars
und Tokenreset verhindern Taskvermischung. Problemantwort nach Phase-0-Schema:
type/title/status/code/request_id; Korrelations-ID im Header, kein unzulässiges neues
Schemafeld. Keine SQL-, Validation-Input- oder Stacktrace-Details für Clients.

HTTPX: explizite Zielnamen, interner Hostkatalog oder externer HTTPS-Modus mit
explizitem cve-egress-proxy:3128. trust_env=False, keine Redirectverfolgung, begrenzte
Pools/Timeouts, sichere TLS-Verifikation. Kein direkter Internet-Fallback. Frei wählbare
Service-Namen sind keine Authentifizierung; echte Dienstauthentifizierung folgt später.
API besitzt weder Egressnetz noch Hostport/Docker-Socket/Netzwerk-Capabilities.
