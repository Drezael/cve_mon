# Nginx-Ingress T00.02.02

Die konkreten Hostnamen/Zertifikate werden in Phase 2 festgelegt, keine öffentlichen Domains
sind im Konzept verbindlich vorgegeben. Phase 2 konkretisiert den Ingress gemäß ADR-0020: HTTPS/443 und optional HTTP/80
für feste GET/HEAD-Weiterleitungen; unverschlüsselte Uploads werden abgewiesen.

| Virtueller Host | Route / Upstream | Identität |
|---|---|---|
| Dashboard | UI → cve-dashboard; /api/v1/* außer technischem Upload → cve-api | Hostgebundene Sitzung; schreibend CSRF, Objektberechtigung |
| API | /api/v1/* außer technischem Upload → cve-api | Eigene gleichoriginige Dashboard-Sitzung, keine CORS-Freigabe zwischen Hosts |
| Technischer Inventar-Host | Ausschließlich POST /api/v1/inventories → cve-api | Verpflichtend verifiziertes Clientzertifikat UND passender API-Token |
| n8n | UI → cve-n8n; keine öffentliche Fachjob-Webhook-Route | Restriktiver Administrationszugang, eigene n8n-Anmeldung, IP-/Netzbeschränkung |

Dashboard-Frontend verwendet seine eigene Origin für API-Aufrufe; Cookies werden nicht zwischen
virtuellen Hosts geteilt. Am API-Host ist eine unabhängige Anmeldung erforderlich.
Der technische Uploadpfad ist an Dashboard-/API-Hosts nicht freigeschaltet. Andere Pfade am
technischen Host liefern 404. n8n ist keine alternative Benutzerverwaltung der Plattform.

Nginx terminiert TLS 1.2/1.3, validiert Clientzertifikatskette, Zweck, Gültigkeit und
konfigurierten Widerrufsstatus. Kein optionales mTLS für den technischen Host.
Nginx entfernt alle vom Client gelieferten Identitäts-/Forwarding-Header und setzt sie kontrolliert.
Das weitergeleitete escaped Clientzertifikat wird ausschließlich auf dem dedizierten, intern
mTLS-geschützten Nginx→API-Weg akzeptiert; API prüft den tatsächlichen TLS-Peer cve-nginx
und berechnet den Zertifikatsfingerprint selbst. Ein frei gesetzter X-Header ist kein Nachweis.
Implementierungsnachweis für TLS-Peerbindung und Zertifikatsweitergabe ist zwingend in Phase 2/API.

Technische Identität: registrierte Zertifikats-SAN, Token-Principal und erlaubte server_id
müssen zusammenpassen. Technische Tokens besitzen ausschließlich inventory:submit und
keinen Zugang zur Dashboard-Administration. API prüft aktuelle Server-/Tokenzustände erneut.

Nginx setzt HSTS nach erfolgreich geprüftem HTTPS-Betrieb, X-Content-Type-Options nosniff,
Referrer-Policy same-origin und eine CSP ohne unsichere Inline-Skripte für das Dashboard;
Frame-Einbettung ist standardmäßig verboten. Auth-/Statusantworten sind no-store.

Inventar-JSON maximal 10 MiB nach Dekodierung, Multipart-Request maximal 11 MiB,
keine komprimierten Uploads/Archive, ein JSON-Dokument pro Request. Überschreitung: 413,
falscher Medientyp: 415, fachliche Validierung: 422, Rate-Limit: 429 mit Retry-After.
Annahme-/Read-Timeout zunächst 30 s; langsame/abgebrochene Übertragungen nicht als angenommen melden.
Anmeldung: 5 Versuche/min je Konto und Quell-IP mit temporärem Backoff; Upload: 10/min pro Principal,
60/min je Quell-IP; normale APIs 120/min pro Sitzung. Limits sind konfigurierbar und später zu messen.
Readiness-/Dienstfehler: 503 in der API, Nginx-Upstreamfehler 502/504. Ein interner
/healthz-Endpunkt prüft nur Nginx, keine Anmeldung und keine sensitiven Detailausgaben.
