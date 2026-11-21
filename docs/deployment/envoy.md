# Envoy aufbauen und betreiben

Offizielles `envoyproxy/envoy` **1.40.2**, Digest
`sha256:8de97e654644827d62afdbf7e1d3dc9fee01a8690d410dd1c63a30dc6b6cecbb` als Basis.
Das aktuelle Projektimage `cve-envoy:1.40.2-phase23` ergänzt die gesperrten Ubuntu-Sicherheitsupdates für apt/libapt-pkg6.0 aus `infrastructure/envoy/packages.lock.json`. Der finale Build ist netzlos.
Keine zusätzlichen Python-Laufzeitbibliotheken. Linux, Docker/Compose, nsenter, nft, ip,
OpenSSL und die Projektvenv sind erforderlich. Der freigegebene Operatorzugang muss eigene
Container-Netznamespaces betreten dürfen. Lokale Ausführung hier mit passwortlosem sudo.

```bash
CVE_DOCKER_SUDO=1 make envoy-policy-check
CVE_DOCKER_SUDO=1 make envoy-check
CVE_DOCKER_SUDO=1 make envoy-up
CVE_DOCKER_SUDO=1 make envoy-test
CVE_DOCKER_SUDO=1 make envoy-down
```

`envoy-up` startet ausschließlich Envoy. `envoy-down` stoppt ausschließlich Envoy und öffnet
keine gesperrten Clientpfade. Ohne Docker-sudo die Variable weglassen; nsenter verwendet bei
Nicht-Root separat das autorisierte `sudo -n`. Fehlende Rechte führen zum Fehler, nicht zum Skip.
Nginx-/DB-Befehle bleiben unabhängig; PostgreSQL-Konfiguration und Datenvolume bleiben erhalten.

## Policy und lebende Clientbindung

`infrastructure/envoy/policies/egress-policy.yml` ist maßgeblich. Regel enthält id, client,
exakten ASCII-FQDN, Port, Protokoll, explizite Methoden, enabled und purpose. Maximal 64 Regeln.
Nur HTTP/80 mit GET/HEAD/POST bzw. HTTPS/443 mit CONNECT. Keine IP-Literale, Wildcards,
Unicode-Mehrdeutigkeit, abschließenden Punkte oder stillschweigend fehlenden Freigabefelder.
ASCII-Punycode kann ausschließlich als ausdrücklich genehmigter konkreter Name verwendet werden.
Die tatsächliche Requestauswertung/Routing erfolgt in Envoy, nicht anhand beliebiger X-Headers.

Neue Policy und explizite eigene Clientnamen als JSON-Datei vorbereiten, zum Beispiel
`{"importer":"cve-project-cve-importer-1","status":"cve-project-cve-service-status-1"}`.
Clientdienste sind in dieser Phase noch nicht produktiv implementiert. Diese Namen sind Beispiele,
keine automatisch entdeckten oder automatisch autorisierten Container. Beim späteren Start:

```bash
CVE_DOCKER_SUDO=1 make envoy-up EGRESS_POLICY=/geschuetzter/pfad/policy.yml EGRESS_CLIENTS=/geschuetzter/pfad/clients.json
```

Das Werkzeug verifiziert Projekt-/Dienstidentität, aktuelle Container-ID/Endpoint-IP/MAC,
Nicht-Root, Capabilities und ausschließlich erlaubte interne Netze. Es rendert eine einzelne
unterstützte v3-Konfiguration, validiert sie mit dem gepinnten echten Envoy, erstellt einen frischen
Envoy-Namespace, installiert die überprüften Namespacefilter und gibt erst danach Listener frei.
Die Runtime erhält ausschließlich read-only Snapshots unter `.runtime/envoy/<projekt>`.
Keine Scheinsplitdateien mit nicht existierendem YAML-Include; die generierte Gesamtdatei ist
vollständig. `infrastructure/envoy/envoy.yaml` dokumentiert die ebenfalls validierte geschlossene
Auslieferungskonfiguration ohne Clientfreigaben. Ein bloßes `docker compose up` wartet ohne
passenden frischen Guard und öffnet keine Listener.

Vor Client-Recreate zuerst Envoy stoppen, Clients kontrolliert neu aufbauen, sämtliche Bindungen
neu prüfen und `envoy-up` ausführen. Keine alte IP/MAC-Liste wiederverwenden. Clients benötigen
cap_drop ALL und dürfen keine Netzadressen/MACs ändern. Dockeradministratoren bleiben vertrauenswürdig.
Nach Proxyrestart ist wegen neuem Boot-/Namespace ein erneutes `envoy-up` notwendig; die alte
Guarddatei genügt nicht. Dies ist bewusst fail closed und benötigt Betreiberreaktion statt Direktfallback.
Für Fachprozesse in Phase 6 wird derselbe Freigabebarrier vor deren Start benötigt. Weitere interne
API-/PostgreSQL-Peers müssen dann port-/dienstgenau in der Clientpolicy ergänzt und getestet werden.

## HTTP-Clients

Nur in den vorgesehenen Backendcontainern setzen, nicht global im Operatorprozess:

```dotenv
HTTP_PROXY=http://cve-egress-proxy:3128
HTTPS_PROXY=http://cve-egress-proxy:3128
NO_PROXY=localhost,127.0.0.1,cve-api,cve-postgres
```

Clients müssen Proxyunterstützung ausdrücklich nutzen und fehlende Pflichtkonfiguration als
Fehler behandeln. Kein `NO_PROXY=*`/pauschales Suffix und keine Zertifikatsprüfung ausschalten.
HTTPS verifiziert den externen Zielnamen/CA durch den Tunnel. urllib wird tatsächlich mit
ProxyHandler/HTTPSHandler geprüft; die spätere konkrete n8n-/Clientversion muss dieselbe
Variablenunterstützung erneut beweisen. Ein fehlender Proxy darf keinen ungeschützten Direktpfad
öffnen; der Kernel-Clientfilter sperrt ihn unabhängig von Bibliothekskonventionen.

## Betrieb, Diagnose und Updates

Health 9901 /healthz prüft Envoys eigene /ready-Antwort über den privaten Adminsocket, nicht
Erreichbarkeit aller Quellen. /metrics bietet Prometheuszahlen für Verbindungen, Upgrades,
SMTP, DNS, Upstreamfehler, Timeouts und Circuitbreaker. Keine Schreib-/Config-/Shutdownrouten.
Adminsocket liegt nur im privaten 0700-Tmpfs. Keine Weiterleitung durch Nginx oder Hostport.

Limits: 256 MiB Container, 128 MiB beobachteter Heap, 1 CPU, zwei Envoythreads, 64 PIDs,
4096 FDs, 64 globale Downstreamverbindungen, je Ziel 64 Verbindungen/Requests und 32 wartende
Requests, 1 MiB Body, 16 KiB Header, 5s Headerdeadline, 30s Requestdeadline und 120s Idle.
CONNECT hat keine normale Requestdeadline, aber Idle- und globale Verbindungsgrenze.
DNS: IPv4-only, höchstens 64 HTTP-Zielcluster plus ein SMTP-Ziel, endliche Resolverarbeit,
2s Querytimeout/ein Versuch, 30s Refresh/TTL und 1–5s Fehlerbackoff; Testpolicy verkürzt Refresh.
Cluster-HTTP-DNS-Felder sind in 1.40.2 noch unterstützt, teilweise als deprecated gekennzeichnet;
ein Versionsupdate muss die dann unterstützte DNS-Cluster-API samt Sicherheitstests erneut prüfen.

JSON-Zugriffslogs ausschließlich mit festen Listener-/Client-/Regelnamen, Zeit, Status/Flags,
Dauer/Bytes, Upstreamadresse und generierter Verbindungs-ID. Keine beliebigen Request-Authoritys,
Pfade/Queries, Header, Bodies oder SMTP-Nutzdaten. Abgelehnte Rohziele werden daher bewusst
nicht unbereinigt ausgegeben. Docker begrenzt Logs auf 3 × 10 MiB, Development ändert dies nicht.

Policyänderung: Datei prüfen, aktive Clients kontrolliert stoppen/neu binden, vollständige Suite,
`envoy-up` mit frischem Namespace. Keine ungeprüfte Live-NFT-/Adminmutation und kein offener
Zwischenzustand. Vor Imageupdate Release/Sicherheitsfixes/Digest prüfen, neue Version im eigenen
Testprojekt validieren, sämtliche DNS/SSRF/SMTP-/Restarttests ausführen, Wartungsfenster planen.
Kein automatisches latest-Pull und kein Fallback auf direkte Quellen oder alternative Smarthosts.

[Testmatrix](../testing/phase-04-test-matrix.md), [Fehlerbehebung](../operations/envoy-troubleshooting.md),
[Sicherheitsgrenzen](../security/egress-security.md).

Die abschließende Bereitschaftsprüfung nach Installation des Namespace-Guards verwendet `--no-recreate`; ein weiterer Image-/Containerwechsel muss den kompletten kontrollierten Start wiederholen. [Phase-23-Updates](../security/phase-23-remediation.md).

Phase 23 entfernt im eigenen Envoy-Image die ungenutzten Login-/PAM-/RPC-/Kerberos-Pakete sowie APT. Der Envoy-Server benötigt laut Linkerauflösung ausschließlich die verbleibenden glibc-Laufzeitbibliotheken. Start und Healthcheck verwenden weiterhin Bash und Coreutils. Nachinstallationen im laufenden Container sind nicht vorgesehen; Änderungen erfolgen über den geprüften Dockerbuild.
