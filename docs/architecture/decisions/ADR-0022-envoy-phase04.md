# ADR-0022: Envoy-Egress, tatsächliche Zieladressen und kontrollierte Clientbindungen

Status: accepted  
Datum: 06.11.2026  
Grundlage: vollständiger Phase-4-Auftrag, T04.01–T04.09, EGR-01–EGR-30.

## Kontext und Problem

Eine Host-Allowlist verhindert keine DNS-Antwort auf eine interne Adresse. Netzwerk-RBAC
kann bei server-first SMTP mit IMMEDIATE eine Upstreamverbindung bereits vor der Prüfung
öffnen. Der Phase-4-Auftrag fordert ausdrücklich den technischen Nachweis beider Grenzen
und gestattet zusätzliche geprüfte Netzwerkfilter. Host-Firewalländerungen sind nicht beauftragt.

## Entscheidung

Offizielles Envoy 1.40.2 mit unveränderlichem Digest. Exakte statische Routen je Client und
Ziel/Port, endliche STRICT_DNS-Cluster statt eines unbeschränkt dynamischen Host-Caches.
Die Cluster lösen DNS dynamisch auf, aber kein Client bestimmt Cluster oder Resolverziel.
HTTPS wird als CONNECT-Raw-Tunnel vermittelt; äußere Requestmethoden sind steuerbar,
innere HTTPS-Methoden/Pfade werden mangels TLS-Entschlüsselung nicht kontrolliert.

Envoy ausschließlich in cve_egress_internal und cve_egress_external, Port 3128 und SMTP
**1587** statt des alten logischen Portplatzhalters 2525. n8n und Statusmonitor bekommen
für ihre späteren autorisierten Proxy-/Health-Verbindungen zusätzlich cve_egress_internal.
Diese ausdrücklich von Phase 4 geforderte Topologie ersetzt die widersprechenden Einträge
des früheren Netzwerkentwurfs. PostgreSQL, Nginx-Netzzuordnung und Ingress bleiben erhalten.

Runtime Envoy UID65532, cap_drop ALL, read-only, keine NET_ADMIN-Capability. Das autorisierte
Linux-Operatorwerkzeug installiert vor Listenerfreigabe per nsenter+nft einen Filter ausschließlich
im überprüften Envoy-Netznamespace. Hostnetz, PID-/Mountnamespace und Host-Firewall werden nicht
umkonfiguriert. Namespace-, Konfigurationshash- und einmaliger Bootnachweis verhindern Freigabe
mit einer alten Bereitschaftsdatei. Fehler/Neustart ohne erneute Guardinstallation bleiben geschlossen.

INPUT lässt nur aktuelle interne IP/MAC/Port-Bindungen ausdrücklich übergebener eigener
Dienstcontainer zu. Labels allein sind keine automatische Autorisierung: Projekt, Dienst,
laufender Container, interne Netze, Nicht-Root und fehlende Capabilities werden zusätzlich geprüft.
SMTP besitzt vor dem IMMEDIATE-TCP-Filter außerdem eine exakte Source-Filterkettenauswahl.
Neue Endpoints mit wiedervergebener IP erben dadurch keine alte MAC-Freigabe. Lifecycle-Regel:
Proxy vor Client-Neuaufbau stoppen, alle Bindungen geprüft neu erzeugen, dann gemeinsam starten.
Dockeradministratoren sind vertrauenswürdig; MAC-Spoofing durch NET_RAW/NET_ADMIN wird bei Clients
nicht zugelassen. Keine dauerhaft hartcodierte Docker-IP und keine Headeridentität als Vertrauen.

Der OUTPUT-Filter sperrt private/reservierte/Host-/Metadatenadressen auf dem tatsächlichen
Socketpfad und erlaubt nur deklarierte öffentliche TCP-Ports. DNS erhält eine enge Resolverausnahme.
IPv6 wird nicht als Upstreamfamilie verwendet und zusätzlich vom Kernel verworfen; AAAA darf
kein Ausweichziel liefern. Autorisierte Clientnamespaces erhalten ebenfalls einen OUTPUT-Filter
zum konkreten Proxy/Port; damit führen manipulierte/fehlende Proxyvariablen und Host-Gateway-
Umwege nicht zu einem direkten Egress. Spätere interne API-/DB-Wege müssen explizit ergänzt
und vor Start der Fachprozesse geprüft werden; es existiert keine pauschale Private-Netz-Ausnahme.

Admin ausschließlich privater Unix-Socket; geschützter Healthlistener 9901 bietet nur feste
GET-Routen /healthz und /metrics. Kein allgemeiner Adminproxy und kein Nginx-Routing darauf.
SMTP ist im Auslieferungszustand deaktiviert, bis ein echter Smarthost vom Betreiber festgelegt
wird. Kein Postfix und keine SMTP-Credentials in Envoy. Die vollständige Funktion wird bereits
mit einem isolierten festen Testsmarthost einschließlich STARTTLS bewiesen.

## Alternativen und Auswirkungen

Ein zusätzlicher Forward-Proxy/DNS-Dienst, ein privilegierter Envoy oder ungeprüfte Hostregeln
würden Umfang bzw. Architektur verändern. Rein deklarative Hostlisten und verspätetes RBAC
erfüllen die Sicherheitsanforderung nicht. Die gewählte Lösung erfordert Linux, nsenter, nft
und den bereits autorisierten privilegierten Operatorzugang für eigene Namespaces.

[Nachweise](../../development/phase-04-acceptance.md),
[Betrieb](../../deployment/envoy.md), [SMTP-Vertrag](../../security/smtp-proxy-security.md).

Quellen: [Envoy-Release](https://github.com/envoyproxy/envoy/releases/tag/v1.40.2),
[HTTP-Upgrades](https://www.envoyproxy.io/docs/envoy/v1.40.2/intro/arch_overview/http/upgrades),
[RBAC-/SMTP-Grenze](https://www.envoyproxy.io/docs/envoy/v1.40.2/configuration/listeners/network_filters/rbac_filter),
[Verbindungsgrenzen](https://www.envoyproxy.io/docs/envoy/v1.40.2/configuration/operations/overload_manager/overload_manager).
