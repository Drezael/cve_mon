# Live-Statuspage T00.02.05

GET /api/v1/dashboard/deployment/status erfordert gültige Anmeldung und deployment:status:read.
Das Dashboard ruft über cve-api den Dienst cve-service-status auf. Jeder Seitenaufruf startet
neue Checks; Antwort mit Cache-Control: no-store und serverseitigem checked_at. Kein stale-cache-Fallback.
Die Seite hängt selbst von Nginx, Dashboard, API und Authentifizierung ab und ist kein externer Monitor.

| Ziel | Methode / Ergebnisgrenze |
|---|---|
| cve-nginx | Internes HTTP /healthz; kein Beweis aller Upstreams |
| cve-egress-proxy | Geschütztes HTTP /ready (Admin 9901); kein beliebiger Adminzugriff |
| cve-n8n | Gepinnter Readiness-Endpunkt; Pfad mit n8n-Version prüfen |
| cve-postgres | Native TLS-Verbindung, Rolle status_probe, SELECT 1; keine Fachtabellen |
| cve-mail-relay | SMTP 220/EHLO/QUIT; keine Testmail, keine Queue-Verwaltung |
| Alle elf Python-Dienste | /health/live und /health/ready; Statusdienst selbst lokaler Liveness-Selfcheck |

Geplantes Manifest: infrastructure/status/status-targets.yml, noch nicht erzeugt.
Schema als Spezifikation: version=1; targets ist eine begrenzte Liste eindeutiger
service_id; pro Ziel enabled (bool), protocol (http/postgres/smtp), host (fester interner
Servicename), port (fester Port), path (nur HTTP), timeout_ms (100–5000), required (bool).
Keine Auth-Secrets im Manifest, stattdessen feste Secret-Referenzen. Keine URLs/Hosts aus
Browserparametern; Redirects der Healthchecks sind verboten. Manifeständerungen sind Deployments.

Parallelität maximal 4, Zieltimeout 2 s, gesamter Request maximal 10 s. Ein Zielausfall wird
isoliert dargestellt; nicht abgeschlossene Checks beim Gesamtdeadline erhalten unknown.
Globale Überlast: 429/Retry-After, keine gecachten Zustände. API/Statusdienst nicht verfügbar: 503.
Für erreichbare Statusprüfung mit Teilfehlern: HTTP 200 mit overall=degraded.

| Zustand | Bedeutung |
|---|---|
| healthy | Liveness erfolgreich, keine vollständige Readiness-Aussage möglich |
| ready | Liveness und verpflichtende Readiness erfolgreich |
| degraded | Teilprüfungen oder optionale Abhängigkeiten fehlerhaft |
| starting | Prozess meldet initialen Startzustand ausdrücklich |
| unreachable | DNS-/Verbindungs-/Zieltimeoutfehler |
| error | Protokoll-/Readinessfehler eines erreichbaren Dienstes |
| unknown | Kein verwertbarer aktueller Nachweis, z.B. Gesamtdeadline |
| disabled | Manifestziel ausdrücklich deaktiviert |

Antwort je Ziel: service_id, state, checked_at, duration_ms und ein sanitierter reason_code.
Keine DSNs, internen Secretpfade, Stacktraces oder Zertifikate in der Browserantwort.
Keine Docker Engine API, kein Socket, keine Host-Bridge und keine Containersteuerung.
Statusprüfungen dürfen weder Dienste neu starten noch fachliche Daten verändern.
