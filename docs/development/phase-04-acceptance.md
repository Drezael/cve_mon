# Phase-4-Gesamtabnahme

Stand: 06.11.2026. **Status: completed.** Alle 45 Aufträge, 46 Abnahmepunkte und 30 Sicherheitsinvarianten
sind lokal nachgewiesen. **473 Tests bestanden** (167 Standard + 77 Envoy + 40 Nginx + 189 PostgreSQL).

## Verbindliche 46 Abnahmepunkte

| Nr. | Kriterium | Ergebnis | Nachweis |
|---|---|---|---|
| 1 | Envoy-Container startbar. | passed | test_envoy_config.py/test_network_isolation.py |
| 2 | Docker-Compose-Konfiguration gültig. | passed | test_envoy_config.py/test_network_isolation.py |
| 3 | Festgelegte Envoy-Version. | passed | test_envoy_config.py/test_network_isolation.py |
| 4 | Keine Verwendung von `latest`. | passed | test_envoy_config.py/test_network_isolation.py |
| 5 | Netzwerkzuordnung korrekt. | passed | test_envoy_config.py/test_network_isolation.py |
| 6 | Kein öffentlicher HTTP-Proxyport. | passed | test_envoy_config.py/test_network_isolation.py |
| 7 | Kein öffentlicher SMTP-Proxyport. | passed | test_envoy_config.py/test_network_isolation.py |
| 8 | Keine privilegierten Container. | passed | test_envoy_config.py/test_network_isolation.py |
| 9 | Kein Docker-Socket. | passed | test_envoy_config.py/test_network_isolation.py |
| 10 | HTTP-Listener auf Port 3128. | passed | test_http_forward_proxy.py/test_https_connect.py |
| 11 | HTTPS CONNECT funktionsfähig. | passed | test_http_forward_proxy.py/test_https_connect.py |
| 12 | Ziel-Allowlist wirksam. | passed | test_http_forward_proxy.py/test_https_connect.py |
| 13 | Client-Allowlist wirksam. | passed | test_http_forward_proxy.py/test_https_connect.py |
| 14 | Nicht erlaubte Hosts blockiert. | passed | test_http_forward_proxy.py/test_https_connect.py |
| 15 | Nicht erlaubte Ports blockiert. | passed | test_http_forward_proxy.py/test_https_connect.py |
| 16 | Kein offener Forward Proxy. | passed | test_http_forward_proxy.py/test_https_connect.py |
| 17 | DNS-Auflösung kontrolliert. | passed | test_dns_security.py/test_network_isolation.py, Kernel-/Zielzähler |
| 18 | DNS-Rebinding geschützt. | passed | test_dns_security.py/test_network_isolation.py, Kernel-/Zielzähler |
| 19 | Private IPv4-Ziele blockiert. | passed | test_dns_security.py/test_network_isolation.py, Kernel-/Zielzähler |
| 20 | Private IPv6-Ziele blockiert. | passed | test_dns_security.py/test_network_isolation.py, Kernel-/Zielzähler |
| 21 | Cloud-Metadatendienste nicht erreichbar. | passed | test_dns_security.py/test_network_isolation.py, Kernel-/Zielzähler |
| 22 | Interne Docker-Netze geschützt. | passed | test_dns_security.py/test_network_isolation.py, Kernel-/Zielzähler |
| 23 | Direkte Proxy-Umgehungen geprüft. | passed | test_dns_security.py/test_network_isolation.py, Kernel-/Zielzähler |
| 24 | SMTP-Listener auf Port 1587. | passed | test_smtp_tcp_proxy.py; fester isolierter Smarthost, Default produktiv deaktiviert |
| 25 | SMTP-Upstream festgelegt. | passed | test_smtp_tcp_proxy.py; fester isolierter Smarthost, Default produktiv deaktiviert |
| 26 | SMTP Server-First funktioniert. | passed | test_smtp_tcp_proxy.py; fester isolierter Smarthost, Default produktiv deaktiviert |
| 27 | SMTP-Banner wird übertragen. | passed | test_smtp_tcp_proxy.py; fester isolierter Smarthost, Default produktiv deaktiviert |
| 28 | STARTTLS-Transparenz geprüft. | passed | test_smtp_tcp_proxy.py; fester isolierter Smarthost, Default produktiv deaktiviert |
| 29 | SMTP-Zielauswahl nicht manipulierbar. | passed | test_smtp_tcp_proxy.py; fester isolierter Smarthost, Default produktiv deaktiviert |
| 30 | Nicht autorisierte SMTP-Clients blockiert. | passed | test_smtp_tcp_proxy.py; fester isolierter Smarthost, Default produktiv deaktiviert |
| 31 | Envoy-Admin-Schnittstelle geschützt. | passed | test_health.py |
| 32 | Health-Endpunkt intern erreichbar. | passed | test_health.py |
| 33 | Health-Endpunkt nicht öffentlich. | passed | test_health.py |
| 34 | Logs ohne Secrets. | passed | test_operations.py; Limits, Logs, Ausfall/Neustart |
| 35 | Ressourcenbegrenzungen aktiv. | passed | test_operations.py; Limits, Logs, Ausfall/Neustart |
| 36 | Circuit Breakers konfiguriert. | passed | test_operations.py; Limits, Logs, Ausfall/Neustart |
| 37 | Fehlerverhalten geprüft. | passed | test_operations.py; Limits, Logs, Ausfall/Neustart |
| 38 | Offlineverhalten geprüft. | passed | test_operations.py; Limits, Logs, Ausfall/Neustart |
| 39 | HTTP-Integrationstests erfolgreich. | passed | vollständige envoy-test Suite mit echten Sockets |
| 40 | HTTPS-Integrationstests erfolgreich. | passed | vollständige envoy-test Suite mit echten Sockets |
| 41 | DNS-/SSRF-Tests erfolgreich. | passed | vollständige envoy-test Suite mit echten Sockets |
| 42 | SMTP-Tests erfolgreich. | passed | vollständige envoy-test Suite mit echten Sockets |
| 43 | Netzwerkisolation nachgewiesen. | passed | vollständige envoy-test Suite mit echten Sockets |
| 44 | Keine nicht freigegebenen Architekturänderungen. | passed | ADR-0022, Betriebs-/Testmatrix, phase-04-handover.md |
| 45 | Dokumentation vollständig. | passed | ADR-0022, Betriebs-/Testmatrix, phase-04-handover.md |
| 46 | Übergabe an Phase 5 vorbereitet. | passed | ADR-0022, Betriebs-/Testmatrix, phase-04-handover.md |

## Sicherheitsinvarianten

| ID | Regel | Nachweisstatus |
|---|---|---|
| EGR-01 | Envoy ist der zentrale Egress Proxy | passed |
| EGR-02 | HTTP-Proxyport 3128 ist nicht öffentlich | passed |
| EGR-03 | SMTP-Proxyport 1587 ist nicht öffentlich | passed |
| EGR-04 | Envoy verwendet nur die vorgesehenen Netzwerke | passed |
| EGR-05 | Kein Docker-Socket | passed |
| EGR-06 | Kein privilegierter Container | passed |
| EGR-07 | Default Deny | passed |
| EGR-08 | Nur erlaubte HTTP-/HTTPS-Ziele | passed |
| EGR-09 | Nur erlaubte Zielports | passed |
| EGR-10 | Nur autorisierte Proxy-Clients | passed |
| EGR-11 | Kein offener HTTP Forward Proxy | passed |
| EGR-12 | HTTPS CONNECT benötigt Zielautorisierung | passed |
| EGR-13 | Keine allgemeine Deaktivierung der TLS-Zertifikatsprüfung | passed |
| EGR-14 | Keine Verbindungen zu internen und reservierten Zieladressen | passed |
| EGR-15 | DNS-Rebinding darf keine Zielbeschränkung umgehen | passed |
| EGR-16 | IPv6 darf keine Sicherheitsrichtlinie umgehen | passed |
| EGR-17 | Kein unkontrollierter direkter Backend-Egress | passed |
| EGR-18 | SMTP besitzt einen festgelegten Upstream | passed |
| EGR-19 | SMTP-Verbindungen werden unmittelbar upstream aufgebaut | passed |
| EGR-20 | Kein allgemeiner SMTP-Relaydienst über Envoy | passed |
| EGR-21 | STARTTLS wird transparent vermittelt | passed |
| EGR-22 | SMTP-Authentifizierung verbleibt bei Postfix | passed |
| EGR-23 | Envoy besitzt keine SMTP-Zugangsdaten | passed |
| EGR-24 | Envoy-Admin ist nicht öffentlich | passed |
| EGR-25 | Der Health-Endpunkt bietet keine allgemeinen Admin-Rechte | passed |
| EGR-26 | Logs enthalten keine Secrets | passed |
| EGR-27 | Ressourcenverbrauch ist begrenzt | passed |
| EGR-28 | Fehler führen nicht zur Aufweichung von Richtlinien | passed |
| EGR-29 | Egress-Richtlinien sind versioniert | passed |
| EGR-30 | Sicherheitsrelevante Änderungen werden getestet | passed |

## Grenzen und Anschlussvoraussetzungen

Die technische Proxy-/SSRF-/SMTP-Schutzkette ist Gegenstand dieser Abnahme, keine bereits
vorhandene Fachanwendung. Ein echter Betreiber-Smarthost wurde nicht angegeben: SMTP bleibt
standardmäßig deaktiviert; der feste konfigurierte Testsmarthost beweist die Funktion mit STARTTLS.
Postfix-Mailqueue, echte SMTP-AUTH-Secrets, korrekte Postfix-TLS-Policysyntax und produktiver
Mailversand folgen ausdrücklich Phase 5. Keine Clients werden allein durch eine deklarierte
Policy autorisiert; lebende Endpoints müssen kontrolliert gebunden werden.

IPv6-Upstreams sind absichtlich geschlossen statt ungeprüft freigegeben. Hostadministration,
Dockerdaemon und der kontrollierte Stop-/Neubindungslifecycle bleiben Vertrauensgrenzen.
Die umfassende spätere Host-Firewallfreigabe aus Phase 2 bleibt erforderlich; die hier bewiesenen
Namespacefilter umgehen diesen Vorbehalt nicht, sondern schützen die eigenen Socketpfade bereits.
Ein Proxyneustart bleibt ohne frischen Guard geschlossen und erfordert den dokumentierten Wiederanlauf.

[Aufgabenstatus](phase-04-status.md), [Testmatrix](../testing/phase-04-test-matrix.md),
[Architekturentscheidung](../architecture/decisions/ADR-0022-envoy-phase04.md).

## Ausgeführte Abschlussprüfungen

| Befehl / Prüfung | Tatsächliches Ergebnis |
|---|---|
| make check | 167 Tests; Ruff-Lint/Format, Mypy strict (52 Pythondateien), YAML/JSON/OpenAPI/Inventarbeispiele, lokale Dokumentverweise, beide Compose-Modelle und Secret-Scan erfolgreich |
| CVE_DOCKER_SUDO=1 make envoy-test | 77 echte Laufzeittests, keine Skips, einschließlich Namespacefilter/DNS/CNAME/IPv6/CONNECT/SMTP/STARTTLS/Logschutz/Idlelimit/IP-MAC-Neubindung; Laufzeit ungefähr drei Minuten |
| CVE_DOCKER_SUDO=1 make infra-test | alle 40 bisherigen Nginx-/TLS-/mTLS-/Netzwerkprüfungen erneut bestanden |
| CVE_DOCKER_SUDO=1 make db-test | alle 189 bisherigen PostgreSQL-Integritäts-/ACL-/Migrations-/Persistenz-/Restoretests erneut bestanden |
| envoy-policy-check / envoy-check | strikte Policy plus echtes gepinntes Envoy-Binary erfolgreich |
| envoy-up und tatsächliche Namespaceprüfung | gesunder normaler Entwicklungscontainer, ausschließlich interne Listener 3128/1587/9901, keine Hostportbindings; Image-EXPOSE10000 ist kein aktiver Listener |
| Defaultauslieferung | keine lebenden Clientfreigaben, produktives HTTP und SMTP ohne echten Betreiber-Smarthost geschlossen |
| Ressourcenbilanz | eigene Testcontainer/-netze vollständig entfernt, normale PostgreSQL-/Nginx-Instanzen gestoppt belassen, vier fremde Nextcloud-Container mit identischen IDs/Ports erhalten |
| Quell-/DB-/Baselinevergleich | 32 geschützte Originalkonzept-/PostgreSQL-/Migrations-/Baseline-Dateien per SHA-256 unverändert |

Offizielles Envoy 1.40.2, Build b2d89e0, Digest
`sha256:8de97e654644827d62afdbf7e1d3dc9fee01a8690d410dd1c63a30dc6b6cecbb`.
Isolierte Standardbibliotheks-Testdienste: Python 3.12.13-Slim-Bookworm, Digest
`sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2`.
Operatorvenv Python 3.12.3; Docker 29.9.2; Compose 5.7.0. Keine neuen Python-/Hostpakete installiert.
Ein gehosteter GitHub-Lauf wurde ohne Commit/Push/Remote nicht behauptet; identische Befehle
sind im Workflow vorbereitet.

Der Logtest übermittelt absichtlich vertrauliche Marker in Query, Authorization, Cookie,
Proxy-Authorization und Request-ID und bestätigt deren vollständige Abwesenheit nach Logflush.
Die Korrelation verwendet die intern erzeugte Verbindungs-ID; Envoys aus Request-ID ableitbare
Stream-ID wird ausdrücklich nicht als vertrauenswürdiger Logwert verwendet.
Die SMTP-Timeoutprüfung senkt das Test-Idlelimit kontrolliert auf eine Sekunde, lässt den
Testsmarthost stumm bleiben und bestätigt den tatsächlichen SMTP-Idle-Timeoutzähler vor Recovery.

[Dateibilanz](phase-04-files.json), [Betrieb](../deployment/envoy.md), [Testmatrix](../testing/phase-04-test-matrix.md).
