# Phase-4-Testmatrix

| Gruppe | Befehl / Datei | Tatsächlicher Nachweis |
|---|---|---|
| Standardprüfungen | make check | Policy-Schema/Negativfälle, Compose-Grenzen, Sourceverträge, Ruff/Mypy, Secret-Scan |
| Envoy-v3 | envoy-check; test_envoy_config.py | echtes gepinntes Binary, YAML-/Filter-/Cluster-/Listener-/Dateifehler mit Fehlerstatus |
| HTTP | test_http_forward_proxy.py | freigegebenes Ziel/GET, unerlaubte Methoden/Ziele/Ports/Userinfo-Umgehung, Redirect, gefälschte Header, Bodylimit, Proxyvariablen |
| CONNECT | test_https_connect.py | echter TLS-Handshake mit CA-/Hostprüfung, getrennte Dienstregeln, unerlaubte Hosts/Ports/Literale und keine Upstream-Accepts |
| DNS/SSRF | test_dns_security.py | echte kontrollierte DNS-Antworten, TTL, öffentliche zu privater Zieländerung, CNAME, AAAA-only/Mischung, NXDOMAIN, Kernel- und Zielzähler |
| SMTP | test_smtp_tcp_proxy.py | passiv abgewarteter Banner, EHLO/mehrzeilige Antwort, echte STARTTLS-/QUIT-Sequenz, falscher Zertifikatsname verweigert, kein Upstream-Accept unberechtigter Clients |
| Netzwerk | test_network_isolation.py | reale Netze/keine Hostports/UID/Capabilities, direkte IP-/SMTP-/HTTPS-/Gateway-/IPv6-Pfade gesperrt, keine cve-Filter im Hostnamespace |
| Betrieb | test_operations.py | strukturierte Logs ohne synthetische Secretmarker, fixer Upstreamausfall/Recovery, globale Verbindungssättigung, Neustartgate/Recovery, erneuerte Endpointbindung, fehlende Proxyvariable und tatsächlicher SMTP-Idleablauf |
| Regression | infra-test und db-test | bisheriger Nginx/TLS-/Netzstand und PostgreSQL-Migrationen/ACLs/Persistenz/Restore |

`make envoy-test` fordert die eigene echte Dockerumgebung an. Kein stiller Skip bei fehlendem
Daemon/Operatorrecht. HTTP-/TLS-/SMTP-/DNS-Testdienste sind temporär; keine produktiven Secrets,
kein echter Mailversand, keine Abhängigkeit von produktiven Sicherheitsdatenquellen.
Alle positiven öffentlichen Testadressen und /32-Routen existieren nur in eigenen Namespaces.
Negative Tests vergleichen zusätzlich tatsächliche TCP-Acceptzähler und nft-Zähler.
Ressourcenbereinigung prüft eigene Projekte/Labels. Nur der normale geschlossene Envoy bleibt
nach der abschließenden Inbetriebnahme als Entwicklungsdienst aktiv.
