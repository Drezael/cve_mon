# Egress-Sicherheitsgrenzen

Default Deny gilt für Proxyclient, Zielhostname, Port, Protokoll und tatsächliche Zieladresse.
Alle produktiven Regeln sind HTTPS/443, HTTP benötigt eine explizite begründete Ausnahme.
Kein Client darf per Request einen Cluster, ein DNS-Ziel, einen Zielport oder eine andere
Clientgruppe wählen. X-Forwarded-/X-Envoy-/Host-Spoofing ersetzt keine Endpointberechtigung.
Redirects verlangen eine neue autorisierte Proxyanfrage; CONNECT entschlüsselt keine inneren Pfade.

Die Regeln werden tatsächlich an zwei Ebenen durchgesetzt: statische Envoy-Routen und der
Kernel des eigenen Netznamespace. Envoy läuft ohne Root/Capabilities und kann seine nft-Regeln
nicht ändern. Die initiale Freigabe wird durch Namespace, Konfigurationshash und einmalige Boot-ID
gebunden. Ein fehlender Filter oder eine fehlgeschlagene Initialisierung gibt keine Listener frei.
Ein nackter Neustart bleibt geschlossen, bis der Operator frische Regeln geprüft installiert.

Die beim Start übergebenen Clients müssen zum richtigen Projekt und Dienst gehören, laufen,
Nicht-Root sein, cap_drop ALL besitzen und ausschließlich erlaubte interne Netze verwenden.
IP plus aktuelle Endpoint-MAC wird pro Listener zugelassen; die eigentlichen Zielregeln sind
zusätzlich pro Client getrennt. Kein pauschaler Netz-CIDR gewährt Proxyzugang. MAC-/IP-Spoofing
ist unprivilegierten Clients ohne NET_RAW/NET_ADMIN nicht möglich. Docker-/Hostadministratoren
bleiben vertrauenswürdig und müssen den dokumentierten Stop-/Neubindungsablauf einhalten.

Gebundene Clientnamespaces erlauben neue Verbindungen ausschließlich zum konkreten Proxyport
und notwendigem internem DNS; Antworten auf zugelassene eingehende Verbindungen bleiben möglich.
Dadurch helfen weder fehlende/manipulierte Proxyvariablen noch eine private Host-Gatewayadresse.
Weitere interne Fach-API-/DB-Wege müssen später einzeln ergänzt werden. Es wird keine umfassende
Fachservice-Kommunikationsmatrix als bereits implementiert ausgegeben.

Die Regeln werden mittels nsenter ausschließlich in überprüften eigenen Namespaces installiert.
Keine Host-INPUT-/FORWARD-/DOCKER-USER- oder Docker-NAT-Regeln werden manuell geändert.
Vor produktivem Plattformbetrieb bleibt der weitergehende Host-Firewallabgleich aus Phase 2
notwendig; die Phase-4-Schutzkette für ihre eigenen ausgehenden Sockets ist hiervon unabhängig
bereits durch lokale Namespacefilter wirksam und tatsächlich getestet.

Angenommene Sicherheitsgrenzen: keine vollständige Übernahme des Hosts/Dockerdaemons,
vertrauenswürdige versionierte Policy-/Operatorartefakte, autorisierte Clientendpoints ohne
Netz-Capabilities und sorgfältige Lifecycle-Steuerung. Eine kompromittierte zugelassene Quelle
wird durch einen Hostnamen nicht zu vertrauenswürdigem CVE-Inhalt; Quellenvalidierung bleibt
Aufgabe späterer Fachadapter. CONNECT kontrolliert keine Anwendungsdaten im verschlüsselten Tunnel.

[DNS/SSRF](dns-ssrf-protection.md), [SMTP](smtp-proxy-security.md),
[Nachweise](../testing/phase-04-test-matrix.md).
