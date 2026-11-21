# Nginx-Betrieb und Routing

Offizielles Image nginx:1.30.6-alpine3.24, unveränderlich gepinnt auf
sha256:dc06c17afbc08d6fe9fbe48159aa81459da2b56baddddc45002f1a68ef77e256.
Herkunft: [Docker Official Image](https://hub.docker.com/_/nginx).
Version/SSL-/SNI-Module wurden mit dem Image selbst geprüft; dies ist keine Behauptung eines vollständigen CVE-Scans.
Aktualisierung bewusst per Digeständerung und kompletter Prüfsequenz, niemals automatisch latest ziehen.

Nginx ist der einzige Produktivcontainer in Phase 2. Nicht-Root, cap_drop ALL,
no-new-privileges, read-only Rootfilesystem und Konfiguration/TLS, 64-MiB-Tmpfs für PID/Temporärdaten,
128 MiB Speicher, 0.5 CPU, 64 PIDs, 4096 Dateideskriptoren, zwei Worker, SIGQUIT zum Beenden.
IP-Forwarding wird im Container für IPv4/IPv6 ausgeschaltet. Keine zusätzlichen Kernel-/Dockerrechte.

| Eingang | Zustand in Phase 2 |
|---|---|
| Bekannte HTTP-Hosts / GET/HEAD | 308 auf feste konfigurierte HTTPS-Authority |
| HTTP / unsichere Methoden | 426, keine Uploadannahme |
| Dashboard/API/n8n HTTPS / | 503, Backend fehlt ausdrücklich |
| Definierte API-Fachpfade | 503; aus OpenAPI abgeleitete Routen, keine Fachverarbeitung |
| Dashboard /api/v1/dashboard/inventories/upload / POST | 503, noch keine Sitzung/CSRF-/Dateiverarbeitung |
| Dashboard/API /api/v1/dashboard/admin/* | 403, bis Backendauthentifizierung gesperrt |
| Technischer Host /api/v1/inventories / POST | mTLS zwingend; gültiger Client erhält 503 |
| Andere technische Pfade | 404; niemals Gruppenadministration |
| Technischer Upload auf Dashboard/API | 404 |
| Dashboard-Datei-Upload auf API-Host | 404; Browserweg ausschließlich Dashboard-Origin |
| Unbekannte Routen | 404 |
| Unbekanntes/fehlendes TLS-SNI | TLS-Handschlag abgelehnt |
| Bekannter TLS-Name / widersprüchlicher Hostheader | 421, kein offener Redirect/Proxy |
| Interner Listener 8081 /healthz | 200/no-store; nie als Hostport veröffentlicht |

Keine Auflösung nicht existierender Backends beim Start. Die 503-Stellen verwenden einen
Content-/try_files-Pfad, damit Rate-Limits in Nginx tatsächlich vor der Antwort greifen.
Ein frühes return 503 würde die Preaccess-Limits umgehen. Fehler bleiben als eigener Status
400/403/404/405/408/413/421/426/429/503 erhalten, kein Erfolgscode als Fallback.

Header: nosniff, same-origin Referrer, CSP default-src none/frame-ancestors none,
DENY, no-store und serverseitige Request-ID, jeweils auch an Fehlerantworten. HSTS nur
production (31536000 Sekunden, kein Preload/includeSubDomains). Finale CSP mit Dashboard abstimmen.
TLS 1.2/1.3, sichere ECDHE/GCM-Auswahl, keine Sessiontickets.
[Offizielle SSL-Dokumentation](https://nginx.org/en/docs/http/ngx_http_ssl_module.html).

Health bestätigt Nginx, nicht die Bereitschaft zukünftiger Backends. Health-Port ist innerhalb
der Container-Netze erreichbar, nicht über öffentliche virtuelle Hosts oder veröffentlichte Ports;
Docker-/Hostadministratoren bleiben vertrauenswürdig. Siehe Netzwerkdokument zur Host-Firewall.

Phase 23 baut `cve-nginx:1.30.6-phase23` vom gepinnten offiziellen Digest. Die im geschlossenen Nginx-Konfigurationsbaum nicht geladenen NJS-/XSLT-Module und deren XML-Bibliotheken werden entfernt. Native Konfigurations-, Ingress-, TLS- und Isolationstests gehören zum Abnahmenachweis.
