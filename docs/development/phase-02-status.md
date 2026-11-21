# Phase-2-Status

Stand: 05.11.2026. **Status: completed — alle 35 Aufträge implementiert und lokal abgenommen.**
142 Standard-/Konfigurationsprüfungen und 40 getrennt angeforderte Docker-Tests bestanden.
Die Host-Firewall-Betriebsvoraussetzung ist gemäß Konzept A33 ausdrücklich offen und vor
Produktivfreigabe zu schließen; kein übersprungener Phase-2-Pflichttest.
Die neue Infrastruktur ist nach Prüfung gestoppt; fremde Ressourcen bleiben unverändert.

| Aufgabe | Titel | Status | Voraussetzung | Implementierung / neue oder geänderte Artefakte | Ergebnis / Sicherheitsprüfung | Abschluss |
|---|---|---|---|---|---|---|
| T02.01.01 | Infrastrukturstand analysieren | completed | Phase 0/1 und freigegebener Dockerzugang | docs/development/phase-02-plan.md (Bestandsaufnahme) | Git/Dateien/Ports/Tools geprüft; fremdes Nextcloud nicht verändert | 05.11.2026 |
| T02.01.02 | Docker-Compose-Basis erstellen | completed | T02.01.01 | compose.yml | Basis syntaktisch und als normalisiertes Modell geprüft | 05.11.2026 |
| T02.01.03 | Entwicklungs-Override erstellen | completed | T02.01.02 | compose.dev.yml | Loopback ohne doppelte additive Ports, eigenes Projektverzeichnis | 05.11.2026 |
| T02.01.04 | Umgebungsvariablen konfigurieren | completed | T02.01.03 | .env.example; scripts/infrastructure/manage.py | Pflichtwerte, Domains, Pfade und Injection-Negativfälle bestanden | 05.11.2026 |
| T02.01.05 | Nginx-Image festlegen | completed | T02.01.04 | compose.yml; docs/deployment/nginx.md | Offizielle Registryherkunft/Digest, nginx -V/SSL/SNI nachgewiesen | 05.11.2026 |
| T02.02.01 | Docker-Netzwerke definieren | completed | T02.01.05 | compose.yml (fünf Netze) | Fünf kanonisch aufgelöste Netze; kein festes Subnetz/globaler Name | 05.11.2026 |
| T02.02.02 | Nginx-Netzwerkzuordnung | completed | T02.02.01 | compose.yml (Nginx ingress/internal) | Effektive Containerzuordnung exakt zwei Netze | 05.11.2026 |
| T02.02.03 | Netzwerkisolation testen | completed | T02.02.02 | tests/infrastructure/test_network_isolation.py | Reale Same-Net-/Cross-Net-/Internetausgangs-/externe Kontrollverbindungen geprüft | 05.11.2026 |
| T02.02.04 | Host-Firewall- und Egress-Konzept | completed | T02.02.03 | docs/security/network-isolation.md | Host/NAT/IPv4/IPv6/Mehrfach-Netzrisiken dokumentiert; Hostregeln vor Produktion offen | 05.11.2026 |
| T02.02.05 | Netzwerk- und Porttests | completed | T02.02.04 | tests/infrastructure/test_network_definitions.py; test_compose_configuration.py | Aufgelöste Modelle und absichtliche Netzwerk-/Portverletzungen geprüft | 05.11.2026 |
| T02.03.01 | Nginx-Konfigurationsstruktur | completed | T02.02.05 | infrastructure/nginx/nginx.conf und snippets/ | nginx -t und Start mit Nicht-Root/Read-only bestanden | 05.11.2026 |
| T02.03.02 | Virtuelle Hosts ohne Backends | completed | T02.03.01 | infrastructure/nginx/conf.d/*.conf.template | Alle Hosts liefern kontrolliert 503 ohne Backend-DNS-Auflösung | 05.11.2026 |
| T02.03.03 | Sichere Nginx-Templates | completed | T02.03.02 | scripts/infrastructure/manage.py; http.conf.template | Explizite Variablenersetzung, Nginx-Variablen bleiben; schadhafte Eingaben abgelehnt | 05.11.2026 |
| T02.03.04 | Proxy-Verträge und Header | completed | T02.03.03 | snippets/proxy-headers.conf; docs/security/mtls-boundaries.md | Headerbereinigung vorbereitet, kein aktiver Backendkanal; Ende-zu-Ende später | 05.11.2026 |
| T02.03.05 | Start-, Reload- und Fehlertests | completed | T02.03.04 | tests/infrastructure/test_nginx_configuration.py | Fehlerprüfung, Start, Restart, wiederholtes Up und Reload bestanden | 05.11.2026 |
| T02.04.01 | Entwicklungszertifikate erzeugen | completed | T02.03.05 | scripts/development/generate-dev-certificates.sh | Lokale CA/SAN/EKU, getrennte Keys 0600; vorhandene PKI bleibt erhalten | 05.11.2026 |
| T02.04.02 | TLS-Konfiguration | completed | T02.04.01 | snippets/tls.conf | TLS1.2/1.3 erfolgreich, TLS1.0/1.1 verweigert | 05.11.2026 |
| T02.04.03 | Dashboard- und API-Hosts | completed | T02.04.02 | 10-dashboard/20-api.conf.template | Getrennte HTTPS-Hosts ohne technisches Clientzertifikat erreichbar (503) | 05.11.2026 |
| T02.04.04 | HTTP-Weiterleitung und Default-Host | completed | T02.04.03 | 00-default.conf.template; ADR-0020 | 308/426/421 und unbekanntes/fehlendes/widersprüchliches SNI/Host geprüft | 05.11.2026 |
| T02.04.05 | Zertifikatswechsel testen | completed | T02.04.04 | tests/infrastructure/test_nginx_configuration.py; docs/deployment/tls-certificates.md | Abgelaufenes/falsches Cert/Kette/Key verweigert, Zertifikat rotiert und zurückgesetzt | 05.11.2026 |
| T02.05.01 | Technischen mTLS-Host erstellen | completed | T02.04.05 | 30-inventory.conf.template | Gültiges mTLS: 503; kein/abgelaufenes/fremdes Cert verweigert | 05.11.2026 |
| T02.05.02 | Client-Identität absichern | completed | T02.05.01 | proxy-headers.conf; docs/security/mtls-boundaries.md | Gefälschte Header umgehen Clientzertifikatsprüfung nicht; spätere Tokenbindung dokumentiert | 05.11.2026 |
| T02.05.03 | Dashboard-Datei-Upload-Route | completed | T02.05.02 | 10-dashboard.conf.template | Browser-Upload ohne technische mTLS-Pflicht: 503, keine Datenannahme | 05.11.2026 |
| T02.05.04 | API- und Verwaltungsrouten trennen | completed | T02.05.03 | conf.d und API-Routensnippet | Technischer Adminpfad 404, Dashboard-Admin 403, unbekannte Pfade 404 | 05.11.2026 |
| T02.05.05 | mTLS- und Routingtests | completed | T02.05.04 | tests/infrastructure/test_ingress_security.py | Alle implementierbaren mTLS-/Routing-Negativfälle bestanden | 05.11.2026 |
| T02.06.01 | Sicherheitsheader | completed | T02.05.05 | security-headers.conf.template | Header genau einmal; Development ohne HSTS, produktive HSTS-Policy isoliert geprüft | 05.11.2026 |
| T02.06.02 | Rate-Limiting und Request-Limits | completed | T02.06.01 | templates/http.conf.template und Serverlocations | 413/429 sowie Headerdeadline und konfigurierte Ressourcen-/Verbindungsgrenzen | 05.11.2026 |
| T02.06.03 | Interner Health-Endpunkt | completed | T02.06.02 | 00-default.conf.template / Listener 8081 | Intern direkt 200/no-store; öffentliche Hosts liefern kein Health | 05.11.2026 |
| T02.06.04 | Logging und Datenschutz | completed | T02.06.03 | logging.conf; Docker-Logrotation | JSON-Logs ohne synthetische Authorization-/Cookie-/Query-/Body-Werte; begrenzte Rotation | 05.11.2026 |
| T02.06.05 | Container-Härtung | completed | T02.06.04 | compose.yml; Container-Sysctls | Effektiver Nicht-Root/Read-only/cap_drop ALL/no-new-privileges und Forwarding aus | 05.11.2026 |
| T02.07.01 | Infrastrukturtests zusammenführen | completed | T02.06.05 | Makefile; Shellwrapper; CI-Workflow | Ein Prüfablauf make check + infra-test; eigene Cleanup-Labels und korrekte Fehlercodes | 05.11.2026 |
| T02.07.02 | Integrationstests durchführen | completed | T02.07.01 | tests/infrastructure und phase-02-test-matrix.md | 142 statische plus 40 Dockerfälle; zusätzliche externe→interne Negativverbindungen bestanden | 05.11.2026 |
| T02.07.03 | Betriebsdokumentation erstellen | completed | T02.07.02 | docs/deployment und docs/operations | Aufbau/Start/Stop/TLS/Reload/Updates/Logs/Fehlerbehebung vollständig | 05.11.2026 |
| T02.07.04 | Status und Übergabe dokumentieren | completed | T02.07.03 | phase-02-plan/status/handover.md | Alle Integrationsgrenzen und Phase-3-Voraussetzungen dokumentiert | 05.11.2026 |
| T02.07.05 | Gesamtabnahme durchführen | completed | T02.07.04 | phase-02-acceptance.md | Gesamtabnahme erfolgreich; keine Produktionsfreigabe ohne Host-/PKI-Nachweise | 05.11.2026 |

Keine Produktivzertifikate, keine Secrets versioniert, keine Backenddienste vorgezogen.
[Dateibilanz und Abnahme](phase-02-acceptance.md), [Übergabe](phase-02-handover.md).
