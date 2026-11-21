# Tatsächlicher DNS-/SSRF-Schutz

Für jeden erlaubten Zielhost gibt es genau einen begrenzten STRICT_DNS-Cluster pro Regel.
Kein Client lädt beliebige Hosts in einen dynamischen Cache und keine dynamischen Host-Overrides.
Die Host-Allowlist gilt vor Routing; nur der konfigurierte Cluster kann einen Upstream auswählen.

Entscheidend ist der OUTPUT-Hook im Envoy-Netznamespace. Er verweigert neue Socketverbindungen
zu Loopback, RFC1918, Carrier-NAT, Link-local/Metadaten, Benchmark-/Dokumentations-/Multicast- und
sonstigen reservierten IPv4-Bereichen sowie allen lokalen Hostadressen. Private Docker-/DB-Netze
sind keine Ausnahmen. IPv6 wird vollständig verworfen; Resolver verwenden V4_ONLY und können
weder AAAA-only noch IPv4-mapped IPv6 als Hintertür verwenden. Nur explizit genehmigte öffentliche
TCP-Ports sind möglich. Eine Quelländerung auf ein verbotenes Netz bleibt auch nach TTL/CNAME/
Cachewechsel blockiert. Es gibt keine getrennte Python-Vorabauflösung mit TOCTOU zum Socket.

DNS hat eine gezielte UDP/TCP-Ausnahme zum konfigurierten Resolver. Der Filter-Hook liegt vor
OUTPUT-DNAT, sodass Docker-DNS 127.0.0.11:53 sicher funktioniert, ohne beliebige Loopbackports
freizugeben. Der Resolver darf kein allgemeines HTTP-/SMTP-Ziel werden. Positive Tests benutzen
einen ausschließlich temporären eigenen DNS-Testserver, keinen zusätzlichen Produktions-DNS-Dienst.

Die Auflösung ist durch höchstens 64 HTTP-Regeln plus ein SMTP-Ziel, Querytimeout und einen
Versuch begrenzt. Nach einem DNS-Fehler kann STRICT_DNS einen zuvor gültigen öffentlichen
Endpoint weiterverwenden; dieser unterliegt weiterhin denselben Kernelregeln. Eine neue
unaufgelöste Quelle erhält keinen beliebigen Ersatzcluster. Ausfälle öffnen keine zusätzlichen Ziele.

Die Tests vergeben eine öffentliche IPv4-Testadresse ausschließlich als Alias in einem eigenen
Testserver-Namespace und eine /32-Route ausschließlich im eigenen Envoy-Testnamespace. Damit
ist der positive öffentliche Adresspfad echt kontrollierbar, ohne reservierte Testnetze in der
Produktionssperrliste freizuschalten oder tatsächlich fremde Internetserver anzusprechen.
Derselbe Server ist zusätzlich privat erreichbar: DNS-Rebinding auf diese private Adresse muss
scheitern und darf dessen TCP-Acceptzähler nicht erhöhen. Weitere Tests: private Bereiche,
Loopback, Metadaten, CNAME auf privates Ziel, AAAA-only, gemischte A/AAAA-Antworten,
NXDOMAIN, TTL-Ablauf und Wiederherstellung. Die tatsächlichen nft-Rejectzähler ergänzen die
HTTP-Fehlerantwort; ein bloßer 403/503 ohne Zielnachweis genügt nicht.

Kein Host-Firewallumbau und keine neue öffentlich erreichbare Route. Vollständige IPv6-Upstreams
sind bewusst nicht freigeschaltet; deren spätere Einführung benötigt gleichwertige Policy- und
Kerneltests. Der Hostbetreiber bleibt für globale Docker-/IPv6-/Routingkonfiguration zuständig.
