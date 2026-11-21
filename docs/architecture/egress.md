# Implementierter Envoy-Egress ab Phase 4

Envoy 1.40.2 ist der zentrale HTTP-/CONNECT- und SMTP-TCP-Egress. Ausschließlich zwei Netze:
cve_egress_internal und cve_egress_external. Keine Hostports, kein Docker-Socket, kein IP-Router.
Clientfreigaben erfolgen je überprüftem Dienstendpoint und Zielregel. Nur der spätere Statusdienst
bekommt den internen lesenden Health-/Metrikenzugang. Nginx ist weiterhin ausschließlich Ingress.

| Listener | Zweck | Zulässige Quellen |
|---|---|---|
| 3128 | explizites HTTP bzw. HTTPS CONNECT | einzelne gebundene importer/enricher/n8n-Endpunkte mit eigenen Zielregeln |
| 1587 | unmittelbarer SMTP-TCP-Tunnel | ausschließlich gebundener mail-relay; standardmäßig deaktiviert |
| 9901 | GET /healthz und /metrics | Loopback-Containerhealthcheck und ausdrücklich gebundener Statusdienst |
| Unix /tmp/envoy-admin.sock | vollständige Administration | ausschließlich lokaler vertrauenswürdiger Operator |

Versionierte Policy: infrastructure/envoy/policies/egress-policy.yml plus striktes JSON-Schema.
Initiale HTTPS-Ziele sind github.com/raw.githubusercontent.com/codeload.github.com für Importer,
services.nvd.nist.gov/www.cisa.gov/security-metadata.canonical.com/ubuntu.com/api.osv.dev für
Enricher. Keine Wildcards; zusätzliche Download-/Redirecthosts erst nach Adapterprüfung freigeben.
n8n erhält standardmäßig keine externen Zielregeln. Ohne explizite lebende Clientbindungen
kann keiner dieser Einträge benutzt werden. Produktives HTTP ist nicht freigegeben.

Endliche statische Zielcluster verwenden kontrolliertes DNS. Der Kernel prüft den tatsächlichen
IP-Pfad, auch bei Rebinding/CNAME/TTL-Wechsel. IPv4-mapped/IPv6-Ausweichwege sind gesperrt.
HTTPS bleibt ohne MITM, der Client prüft CA und externen Zielnamen. CONNECT kann keine innere
GET-/POST-/Pfadpolicy erzwingen; OSV-POST bleibt Aufgabe des späteren freigegebenen Adapters.

Namespacefilter für Envoy und gebundene Test-/Fachclients verhindern direkte Umgehungen.
Sie verändern keine Host-Firewall. Fremde Docker-Ressourcen bleiben unverändert.
PostgreSQL ist kein Proxyziel. Neue interne API-/DB-Verbindungen werden in der zugehörigen
Fachphase ausdrücklich in der Client-Namespacepolicy ergänzt, niemals durch privaten Netzfreibrief.

[Architekturentscheidung](decisions/ADR-0022-envoy-phase04.md), [Betrieb](../deployment/envoy.md),
[DNS/SSRF](../security/dns-ssrf-protection.md), [SMTP/Phase 5](../security/smtp-proxy-security.md).
