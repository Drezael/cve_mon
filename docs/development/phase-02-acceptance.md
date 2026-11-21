# Phase-2-Gesamtabnahme T02.07.05

Stand: 05.11.2026. **Status: completed — lokale Entwicklungsinfrastruktur vollständig abgenommen.**
Alle 35 Einzelaufträge abgeschlossen; [Status und Einzelnachweise](phase-02-status.md).
**Keine Produktivfreigabe**, bis die explizit offenen Host-Firewall-/Egress-/PKI-Betriebsanforderungen
nachgewiesen sind. Das entspricht Konzept A33 und ist kein als bestanden deklarierter Hostregeltest.

## Ergebnis

Docker-Compose-Basis und isolierbarer Entwicklungs-Override, fünf Netzwerkdefinitionen,
Nicht-Root/Read-only-Nginx, HTTPS/TLS1.2/1.3, verpflichtendes technisches mTLS, getrennte
virtuelle Hosts/Routen, kontrollierte 503/403/404-Fehler, sichere Templates, Header und Limits,
interner Health, sichere JSON-Logs, Rotation/Reload sowie Tests und Betriebsdokumentation.
Aktuell ausschließlich Nginx; keine Datenannahme, Benutzerverwaltung oder Fachbackend.

## Versionen und tatsächlich ausgeführte Prüfungen

- Docker Engine 29.9.2; Compose v5.7.0; Linux; Python 3.12.3; Host-OpenSSL 3.0.13.
- Offizielles Nginx 1.30.6/Alpine3.24 mit OpenSSL 3.5.9 zur Laufzeit; SSL-/SNI-Module per nginx -V geprüft.
- Registryindex: nginx:1.30.6-alpine3.24@sha256:dc06c17afbc08d6fe9fbe48159aa81459da2b56baddddc45002f1a68ef77e256.
- Compose speichert denselben unveränderlichen Index als nginx@sha256-Referenz; keine latest-Auflösung.
- **make check: 142 bestanden**, 40 Runtimefälle bewusst separat ausgewählt.
- **make infra-test: 40 bestanden**, keine Skips; vollständige [Testmatrix](../testing/phase-02-test-matrix.md).
- Netzwerkfall zusätzlich nach Erweiterung um externe→interne Verweigerung erfolgreich wiederholt.
- Ruff/Formatierung, striktes Mypy (18 Dateien), YAML/JSON/OpenAPI/Schema/Beispiele,
  beide Compose-Modelle und Secret-Prüfung erfolgreich.
- nginx -t, TLS-/Clientketten/Schlüsselpaar, abgelaufene/falsche Ersatzcerts, Rotation,
  Reload, Restart, wiederholter Start, HSTS-/Header-/Rate-/Größen-/Timeoutfälle geprüft.
- Make-/Shell-Einstiege geprüft, vollständiges eigenes Dev-Deployment gestartet, geprüft und gestoppt.
- Tatsächlicher Netzwerk-/Mount-/Port-/User-/Capability-/Read-only-/Forwardingzustand inspiziert.

## Gesamtabnahmematrix

| Abnahme | Prüfung | Nachweis / Ergebnis |
|---|---|---|
| A02-01 | Compose-Dateien gültig. | Beide Modelle normalisiert und durch Compose-CLI geprüft |
| A02-02 | Entwicklungsumgebung startbar. | Eigener Loopback-Teststack tatsächlich gestartet |
| A02-03 | Produktivkonfiguration definiert. | Basis ohne Dev-Override definiert; nicht produktiv deployed |
| A02-04 | Netzwerke korrekt. | Fünf Definitionen geprüft, Nginx genau zwei zugeordnet |
| A02-05 | Interne Netzwerke isoliert. | Same-Net/Cross-Net und externer Kontrollversuch bestanden |
| A02-06 | Nginx startbar. | Container health=healthy, nginx -t erfolgreich |
| A02-07 | Nginx ohne Backends startbar. | Keine Upstreams/DNS-Abhängigkeit zu fehlenden Diensten |
| A02-08 | HTTPS funktionsfähig. | CA-/Hostname-geprüfte HTTPS-Aufrufe erfolgreich |
| A02-09 | TLS-Konfiguration sicher. | TLS1.2/1.3 positiv, TLS1.0/1.1 negativ |
| A02-10 | Entwicklungszertifikate erzeugbar. | Lokale kurzlebige PKI erfolgreich erzeugt, keine Überschreibung |
| A02-11 | Keine privaten Schlüssel im Git-Repository. | Nur ignorierte lokale Schlüssel; Secret-Scanning ohne Funde |
| A02-12 | Dashboard-Host erreichbar. | 503 ohne technische Clientzertifikatspflicht |
| A02-13 | API-Host erreichbar. | 503 auf getrennter HTTPS-Origin |
| A02-14 | n8n-Host vorbereitet. | 503, keine aktive n8n-Verwaltung |
| A02-15 | Inventar-Host mit verpflichtendem mTLS. | ssl_verify_client on; echter Clienttest |
| A02-16 | Ungültige Client-Zertifikate abgelehnt. | Untrusted-/expired-Clients abgelehnt |
| A02-17 | Fehlende Client-Zertifikate abgelehnt. | Ohne Zertifikat kein Uploadzugang |
| A02-18 | Dashboard ohne technisches mTLS erreichbar. | Dashboard ohne mTLS liefert 503 |
| A02-19 | Administrative Routen nicht ungeschützt. | Admin 403 beziehungsweise 404 auf technischem Host |
| A02-20 | Unbekannte Hosts abgelehnt. | SNI/Host unbekannt oder widersprüchlich abgelehnt |
| A02-21 | HTTP-Weiterleitung korrekt. | Feste Authority/308, unsichere HTTP-Methoden 426 |
| A02-22 | Sicherheitsheader korrekt. | Header genau einmal, HSTS nur Produktivpolicy |
| A02-23 | Request-Limits funktionsfähig. | Übergröße 413, Headerdeadline begrenzt |
| A02-24 | Rate-Limiting geprüft. | Flood führt 429 vor fehlendem Backend |
| A02-25 | Interner Health-Endpunkt funktionsfähig. | Interner Wget-/Netzwerkzugriff liefert 200/no-store |
| A02-26 | Health-Endpunkt nicht öffentlich. | Öffentliche /healthz-Requests liefern kein Health |
| A02-27 | Keine unnötigen Hostports. | Nur Loopback-HTTP/HTTPS, kein Datenbank-/Health-Publishing |
| A02-28 | Keine Docker-Socket-Mounts. | Aufgelöste und effektive Mounts ohne Docker-Socket |
| A02-29 | Keine privilegierten Container. | HostConfig Privileged=false, User unprivilegiert |
| A02-30 | Logs ohne Geheimnisse. | Synthetische Auth-/Cookie-/Query-/Body-Marker fehlen in JSON-Logs |
| A02-31 | Neustart und Reload erfolgreich. | Restart/Idempotenz/Reload/Rotation erfolgreich |
| A02-32 | Netzwerkisolation nachgewiesen. | Echte Docker-Verbindungstests inklusive extern→intern bestanden |
| A02-33 | Offene Host-Firewall-Voraussetzungen dokumentiert und vor einer Produktivfreigabe verbindlich zu schließen. | Dokumentiert und OFFEN vor Produktivfreigabe; keine Hoständerung |
| A02-34 | Automatisierte Infrastrukturtests erfolgreich. | 142 Standard- und 40 Infrastrukturtests bestanden |
| A02-35 | Deployment-Dokumentation vollständig. | Aufbau/Betrieb/TLS/Fehlerbehebung dokumentiert |
| A02-36 | Übergabe an Phase 3 erstellt. | Phase-3-Netz/DB-/Persistenz-/Healthgrenzen übergeben |
| A02-37 | Keine unzulässigen Architekturänderungen. | Nur expliziter Phase-2-HTTP-Redirect per ADR-0020 abgeglichen |
| A02-38 | Keine fachlichen Backend-Dienste vorzeitig implementiert. | Nur Nginx im Deployment, keine Fachbackend-Implementierung |


## Bestands- und Architekturabgleich

Phase 0/1 blieben Grundlage. ADR-0020 dokumentiert die explizite neue Port-80-Redirectvorgabe;
service-access-v1.json Version 1.1 und zugehörige Validator-/Dokumentationserwartungen sind angepasst.
Phase-1-Tests wurden gezielt von "keine Compose-Dateien" auf "keine vorgezogenen Backends"
und die erweiterte, dokumentierte Umgebungsvorlage fortgeschrieben. make validate prüft jetzt
beide Compose-Modelle; Hosted-CI führt zusätzlich die Docker-Tests aus, sobald veröffentlicht.
Keine Testanforderung wurde still entfernt oder ein fehlender Backendtest als Erfolg ausgegeben.

Docker-Zugriff war zunächst verweigert. Der Nutzer hat ausdrücklich passwortloses sudo
für die Dockeraufgaben freigegeben. Die Skripte erfordern dafür CVE_DOCKER_SUDO=1;
keine automatische Gruppen-/Socket-/Host-Firewalländerung. Vier fremde Nextcloud-Container
wurden vor/nach den Tests unverändert vorgefunden. Sämtliche temporären eigenen Ressourcen
wurden labelgebunden entfernt, der normale Entwicklungsstack anschließend mit infra-down gestoppt.
Imagecache und ignorierte lokale PKI/Test-Snapshots bleiben für reproduzierbare Entwicklung erhalten.

## Neue und geänderte Dateien

Gegenüber dem Stand zu Beginn dieses Auftrags: 51 neue und 23 geänderte versionierbare Dateien.

Neue Dateien:

```text
compose.dev.yml
compose.yml
docs/architecture/decisions/ADR-0020-http-ingress-phase02.md
docs/deployment/docker-compose.md
docs/deployment/environments.md
docs/deployment/maintenance.md
docs/deployment/nginx.md
docs/deployment/tls-certificates.md
docs/development/phase-02-acceptance.md
docs/development/phase-02-handover.md
docs/development/phase-02-plan.md
docs/development/phase-02-status.md
docs/operations/nginx-troubleshooting.md
docs/security/ingress-security.md
docs/security/mtls-boundaries.md
docs/security/network-isolation.md
docs/testing/phase-02-test-matrix.md
infrastructure/envoy/README.md
infrastructure/mail/README.md
infrastructure/n8n/README.md
infrastructure/nginx/README.md
infrastructure/nginx/conf.d/00-default.conf.template
infrastructure/nginx/conf.d/10-dashboard.conf.template
infrastructure/nginx/conf.d/20-api.conf.template
infrastructure/nginx/conf.d/30-inventory.conf.template
infrastructure/nginx/conf.d/40-n8n.conf.template
infrastructure/nginx/nginx.conf
infrastructure/nginx/snippets/errors.conf
infrastructure/nginx/snippets/logging.conf
infrastructure/nginx/snippets/proxy-headers.conf
infrastructure/nginx/snippets/security-headers.conf.template
infrastructure/nginx/snippets/tls.conf
infrastructure/nginx/templates/README.md
infrastructure/nginx/templates/http.conf.template
infrastructure/postgres/README.md
infrastructure/status/README.md
scripts/development/generate-dev-certificates.sh
scripts/infrastructure/check-nginx-config.sh
scripts/infrastructure/manage.py
scripts/infrastructure/preflight.sh
scripts/infrastructure/test-mtls.sh
scripts/infrastructure/test-network-isolation.sh
scripts/infrastructure/test-tls.sh
tests/infrastructure/client.py
tests/infrastructure/conftest.py
tests/infrastructure/fixtures/compose.network-audit.yml
tests/infrastructure/test_compose_configuration.py
tests/infrastructure/test_ingress_security.py
tests/infrastructure/test_network_definitions.py
tests/infrastructure/test_network_isolation.py
tests/infrastructure/test_nginx_configuration.py
```

Geänderte Dateien:

```text
.env.example
.github/workflows/quality.yml
.gitignore
Makefile
README.md
contracts/security/README.md
contracts/security/service-access-v1.json
docs/architecture/README.md
docs/architecture/components.md
docs/architecture/decisions/README.md
docs/architecture/ingress.md
docs/architecture/networks.md
docs/architecture/open-points.md
docs/development/developer-setup.md
docs/development/development-status.md
docs/development/phase-00-acceptance.md
docs/development/phase-01-acceptance.md
infrastructure/README.md
pyproject.toml
scripts/validate_contracts.py
scripts/validate_repository.py
tests/unit/test_development_configuration.py
tests/unit/test_repository_structure.py
```

Alle drei Originalkonzepte in dev_docs und die leere Secret-Baseline sind per SHA-256
unverändert. Keine echten Zugangsdaten, produktiven Schlüssel, Commits oder Pushes.
Lokal erzeugte Testschlüssel liegen ausschließlich in ignorierten Verzeichnissen, Modus 0600.
Keine Änderung am externen Ansible-Projekt oder an fremden Docker-Ressourcen.

## Offene Grenzen und Übergabe

Host-Firewall/DOCKER-USER/nftables, IPv6-Gleichwertigkeit, erlaubter Host-/Egresszugriff,
produktive Zertifikats-/Widerrufsinfrastruktur und tatsächliche Produktionsdomains müssen vor
Produktivfreigabe betriebsseitig nachgewiesen werden. Die Tests bestätigen die gemessenen
Docker-Netzgrenzen, nicht eine unangetastete globale Hostfirewall.

Die vollständige Nginx→Backend-Peer-/Token-/Serverbindung sowie Sitzungen/CSRF/MFA bleiben
Phase 8/11; der aktuelle Proxy leitet keine behauptete Identität an ein Backend weiter.
WebSocket-/Backendrouten, finale Dashboard-CSP und Principal-Limits erst bei Integration freigeben.
Gehostete GitHub-CI wurde ohne Remote/Push nicht ausgeführt; lokale Workflowbefehle sind geprüft.
Separate Originale Gesamtkonzept 3.12/Entwicklungsplan 1.2 bleiben nachzureichen/abzugleichen.

[Übergabe an Phase 3 und spätere Integrationen](phase-02-handover.md).
Phase 3 wurde nicht begonnen. Start der geprüften lokalen Infrastruktur: make dev-certs
(nur wenn noch keine PKI vorhanden), danach CVE_DOCKER_SUDO=1 make infra-up bei autorisiertem Docker-sudo.
