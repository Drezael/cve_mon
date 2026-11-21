# Docker-Netzwerkisolation und offene Hostvoraussetzungen

Fünf projektbezogene Bridges, keine festen Subnetze/globalen Namen:
cve_ingress und cve_egress_external extern routbar; cve_internal, cve_data und
cve_egress_internal internal=true. IPv6 ist bis zur gleichwertigen Härtung deaktiviert.
Nginx ausschließlich ingress/internal; keine Datenbank-/Egress-Netze, kein Default-Netz.
Nur Loopback-HTTP/HTTPS in Entwicklung, nie Health-/Datenbankport publiziert.

Tests weisen reale Kommunikation im selben internen Netz, Verweigerung zwischen getrennten
internen Netzen, fehlende externe TCP-Verbindung aus internal/data und eine erfolgreiche
externe Kontrollverbindung von einem externen Testnetz nach. Positive Internetkontrolle ist
1.1.1.1:443; fällt sie aus, ist der Test nicht bestanden, statt Isolation aus fehlendem Internet
zu folgern. Testcontainer haben keine zusätzlichen Rechte oder Host-/Socketmounts.

internal=true verhindert keinen Zugriff aller Hostprozesse auf alle Docker-Netze und ist
kein Least-Privilege-Regelwerk zwischen Teilnehmern derselben Bridge. Nginx ist mehrfach
angebunden: IP-Forwarding im Container aus, keine NET_ADMIN-/privileged-Rechte, kein allgemeiner
HTTP-/CONNECT-Proxy. Dies ersetzt keine Host-Firewall für vollständigen Egressschutz.

## Vor Produktivfreigabe verbindlich zu schließen

Docker richtet Publishing/NAT und eigene Filterregeln ein. Host-UFW allein garantiert keine
Docker-Portkontrolle. Zuständiger Betreiber muss DOCKER-USER/nftables-Regeln passend zur
Engine festlegen und messen: nur vorgesehenes Ingressziel, kein direkter Backend-/Metadaten-/
privater Egress, keine unerlaubten Inter-Bridge-/Hostdienstzugriffe, IPv4/IPv6 gleichwertig.
Docker-Subnetze erst aus dem konkreten Deployment ableiten, keine ungeprüften statischen Netze.
Mehrfach-Netzteilnehmer und Host-Gateways ausdrücklich testen; spätere Backenddienste erhalten
keinen allgemeinen Internet-Fallback. Envoy allein übernimmt freigegebenen Egress.

Diese zusätzlichen Hostregeln wurden nicht verändert und sind keine behauptete wirksame
Produktivfirewall. Die Phase-2-Entwicklungsabnahme bestätigt Docker-Bridge-Grenzen;
Produktivfreigabe bleibt bis zum betrieblichen Nachweis gesperrt (Konzept T02.02.04/A33).
Keine vorhandenen fremden Docker-Ressourcen wurden verändert.

## Gelesener Hostzustand bei der Abnahme

Read-only geprüft: iptables -S DOCKER-USER meldete eine vorhandene, in dieser Kette
unbestückte Userchain; Host-IPv4-Forwarding war 1, IPv6-Forwarding 0. Daraus folgt keine
Aussage über sämtliche anderen Hostfilter. Docker verwaltet seine eigenen Bridge-/NAT-Regeln
beim Testbetrieb; zusätzliche projektspezifische Betreiberregeln wurden nicht gesetzt.
Die fehlende vollständige Egress-/Host-Freigabe bleibt deshalb ausdrücklich offen.


## Ergänzung Phase 23

Vorhandene sieben Netzwerkzonen bleiben erhalten. Nur Nginx veröffentlicht die vorgesehenen HTTP/HTTPS-Ports. PostgreSQL und n8n-Administration sind nicht zusätzlich veröffentlicht. Inventory-/Matching-/Findingworker erhalten keinen freien Internetzugang. Importer/Enricher und Postfix verwenden den vorhandenen Envoy mit festen Hosts, DNS-/Adressprüfung und pro Projekt/Namespace installierten Guards.

Tests/infrastructure, envoy und mail prüfen positive Pflichtverbindungen und negative Direkt-, DNS-, IPv6-, private IP-, Metadaten-, SMTP- und CONNECT-Ziele. Ein ausgefallener Proxy aktiviert keinen Direktfallback. Wiederanlauf erfolgt über bestehende Controller, damit Containeridentität und Namespace-Guard zusammenpassen. Keine pauschalen Firewalländerungen oder globalen Docker-Prunes. Testpräfixe und Volumelabels begrenzen das Cleanup.
